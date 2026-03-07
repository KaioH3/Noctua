package monitor

import (
	"context"
	"fmt"
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
}

type ProcessMonitor struct {
	bus      *event.Bus
	cfg      *config.Config
	known    map[int32]procSnapshot
	mu       sync.Mutex
	learning bool
}

func NewProcessMonitor(bus *event.Bus, cfg *config.Config) *ProcessMonitor {
	return &ProcessMonitor{
		bus:      bus,
		cfg:      cfg,
		known:    make(map[int32]procSnapshot),
		learning: true,
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

		snap := procSnapshot{
			PID:     pid,
			Name:    name,
			Exe:     exe,
			Created: created,
		}

		pm.mu.Lock()
		_, exists := pm.known[pid]
		pm.known[pid] = snap
		pm.mu.Unlock()

		if exists || learning {
			continue
		}

		if pm.isTrusted(name) {
			continue
		}

		e := event.Event{
			Timestamp: time.Now(),
			Source:    "process",
			Kind:     "new_process",
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
		if name == t {
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
