package monitor

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/process"

	"noctua/internal/config"
	"noctua/internal/event"
)

type procSnapshot struct {
	PID     int32
	Name    string
	Exe     string
	Created time.Time
	PPID    int32
}

type ProcessMonitor struct {
	bus        *event.Bus
	cfg        *config.Config
	known      map[int32]procSnapshot
	mu         sync.Mutex
	learning   bool
	spawnTimes map[int32][]time.Time // PPID → child spawn timestamps
	spawnMu    sync.Mutex
}

func NewProcessMonitor(bus *event.Bus, cfg *config.Config) *ProcessMonitor {
	return &ProcessMonitor{
		bus:        bus,
		cfg:        cfg,
		known:      make(map[int32]procSnapshot),
		spawnTimes: make(map[int32][]time.Time),
		learning:   true,
	}
}

func (pm *ProcessMonitor) SetLearning(v bool) {
	pm.mu.Lock()
	pm.learning = v
	pm.mu.Unlock()
}

func (pm *ProcessMonitor) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(pm.cfg.ScanIntervalSec) * time.Second)
	defer ticker.Stop()

	// initial scan
	pm.scan()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pm.scan()
		}
	}
}

func (pm *ProcessMonitor) scan() {
	procs, err := process.Processes()
	if err != nil {
		return
	}

	pm.mu.Lock()
	learning := pm.learning
	pm.mu.Unlock()

	current := make(map[int32]bool, len(procs))

	for _, p := range procs {
		pid := p.Pid
		current[pid] = true

		name, _ := p.Name()
		exe, _ := p.Exe()
		createTime, _ := p.CreateTime()
		created := time.UnixMilli(createTime)
		ppid, _ := p.Ppid()

		snap := procSnapshot{
			PID:     pid,
			Name:    name,
			Exe:     exe,
			Created: created,
			PPID:    ppid,
		}

		pm.mu.Lock()
		_, exists := pm.known[pid]
		pm.known[pid] = snap
		pm.mu.Unlock()

		if exists || learning {
			continue
		}

		// Track child spawns per parent for spawn-loop detection.
		now := time.Now()
		if ppid > 0 {
			pm.recordSpawn(ppid, now)
			if count := pm.spawnCount(ppid, now); count >= pm.cfg.ResourceGuard.SpawnLoopLimit {
				parentSnap := pm.knownSnap(ppid)
				pm.bus.Publish(event.Event{
					Timestamp: now,
					Source:    "process",
					Kind:      "spawn_loop",
					EntityID:  fmt.Sprintf("proc:spawn:%d", ppid),
					Details: map[string]any{
						"pid":        ppid,
						"name":       parentSnap.Name,
						"exe":        parentSnap.Exe,
						"child_count": count,
						"window_sec": pm.cfg.ResourceGuard.SpawnLoopWindow,
					},
					Message: fmt.Sprintf("Spawn loop: %s (PID %d) spawned %d children in %ds",
						parentSnap.Name, ppid, count, pm.cfg.ResourceGuard.SpawnLoopWindow),
				})
			}
		}

		if pm.isTrusted(name) {
			continue
		}

		e := event.Event{
			Timestamp: now,
			Source:    "process",
			Kind:      "new_process",
			EntityID:  fmt.Sprintf("proc:%d:%s", pid, name),
			Details: map[string]any{
				"pid":     pid,
				"name":    name,
				"exe":     exe,
				"created": created.Format(time.RFC3339),
			},
			Message: fmt.Sprintf("New process: %s (PID %d) exe=%s", name, pid, exe),
		}

		pm.bus.Publish(e)
	}

	// detect terminated processes (cleanup known map)
	pm.mu.Lock()
	for pid := range pm.known {
		if !current[pid] {
			delete(pm.known, pid)
		}
	}
	pm.mu.Unlock()
}

func (pm *ProcessMonitor) isTrusted(name string) bool {
	for _, t := range pm.cfg.TrustedProcesses {
		if strings.HasSuffix(t, "*") {
			if strings.HasPrefix(name, t[:len(t)-1]) {
				return true
			}
		} else if name == t {
			return true
		}
	}
	return false
}

func (pm *ProcessMonitor) KnownCount() int {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return len(pm.known)
}

func (pm *ProcessMonitor) knownSnap(pid int32) procSnapshot {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.known[pid]
}

func (pm *ProcessMonitor) recordSpawn(ppid int32, ts time.Time) {
	pm.spawnMu.Lock()
	defer pm.spawnMu.Unlock()
	pm.spawnTimes[ppid] = append(pm.spawnTimes[ppid], ts)
}

// spawnCount returns how many children ppid has spawned within the configured
// window, pruning old entries as a side effect.
func (pm *ProcessMonitor) spawnCount(ppid int32, now time.Time) int {
	pm.spawnMu.Lock()
	defer pm.spawnMu.Unlock()

	window := time.Duration(pm.cfg.ResourceGuard.SpawnLoopWindow) * time.Second
	cutoff := now.Add(-window)

	times := pm.spawnTimes[ppid]
	i := 0
	for i < len(times) && times[i].Before(cutoff) {
		i++
	}
	pm.spawnTimes[ppid] = times[i:]
	return len(pm.spawnTimes[ppid])
}
