package monitor

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	goproc "github.com/shirou/gopsutil/v3/process"

	"noctua/internal/config"
	"noctua/internal/event"
)

type cpuSample struct {
	value float64
	ts    time.Time
}

// welfordStats tracks running mean and variance using Welford's online algorithm.
// This gives a stable per-process-name CPU baseline with O(1) memory.
type welfordStats struct {
	n    float64
	mean float64
	m2   float64 // sum of squared deviations
}

func (w *welfordStats) update(x float64) {
	w.n++
	delta := x - w.mean
	w.mean += delta / w.n
	delta2 := x - w.mean
	w.m2 += delta * delta2
}

// stddev returns the sample standard deviation (0 if fewer than 2 samples).
func (w *welfordStats) stddev() float64 {
	if w.n < 2 {
		return 0
	}
	return math.Sqrt(w.m2 / (w.n - 1))
}

// ResourceMonitor polls every ScanIntervalSec for CPU% and RSS memory per PID.
// It maintains:
//   - A per-PID sliding window of CPU readings for sustained detection
//   - A per-process-name Welford baseline using adaptive thresholds:
//     effective_cpu_threshold = max(config_threshold, learned_mean + 3σ)
//     This prevents false alarms for known-heavy processes like games.
//
// Events emitted:
//
//	"cpu_abuse"    — CPU exceeded effective threshold for SustainedSeconds
//	"memory_abuse" — RSS exceeded MemoryThresholdMB
//
// A 60-second cooldown per PID per kind prevents event storms.
type ResourceMonitor struct {
	bus      *event.Bus
	cfg      *config.Config
	handles  map[int32]*goproc.Process
	cpuHist  map[int32][]cpuSample
	memAlert map[int32]time.Time
	cpuAlert map[int32]time.Time
	// Adaptive baseline: keyed by process name (so all PIDs with same name share it).
	baseline map[string]*welfordStats
	mu       sync.Mutex
}

func NewResourceMonitor(bus *event.Bus, cfg *config.Config) *ResourceMonitor {
	return &ResourceMonitor{
		bus:      bus,
		cfg:      cfg,
		handles:  make(map[int32]*goproc.Process),
		cpuHist:  make(map[int32][]cpuSample),
		memAlert: make(map[int32]time.Time),
		cpuAlert: make(map[int32]time.Time),
		baseline: make(map[string]*welfordStats),
	}
}

func (rm *ResourceMonitor) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(rm.cfg.ScanIntervalSec) * time.Second)
	defer ticker.Stop()

	// Initial scan primes the CPU delta baseline (first result is always 0).
	rm.scan()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rm.scan()
		}
	}
}

func (rm *ResourceMonitor) scan() {
	rg := &rm.cfg.ResourceGuard
	if !rg.Enabled {
		return
	}

	procs, err := goproc.Processes()
	if err != nil {
		return
	}

	now := time.Now()
	activePIDs := make(map[int32]bool, len(procs))

	for _, p := range procs {
		pid := p.Pid
		activePIDs[pid] = true

		rm.mu.Lock()
		handle, ok := rm.handles[pid]
		if !ok {
			handle = p
			rm.handles[pid] = handle
		}
		rm.mu.Unlock()

		// CPU% since last call — first call always 0, subsequent calls accurate.
		cpuPct, err := handle.CPUPercent()
		if err != nil {
			continue
		}

		memInfo, err := handle.MemoryInfo()
		if err != nil {
			continue
		}

		name, _ := handle.Name()
		exe, _ := handle.Exe()

		rm.mu.Lock()

		// Update per-name adaptive baseline with current CPU reading.
		if _, ok := rm.baseline[name]; !ok {
			rm.baseline[name] = &welfordStats{}
		}
		rm.baseline[name].update(cpuPct)
		bl := rm.baseline[name]
		adaptiveThreshold := math.Max(rg.CPUThreshold, bl.mean+3*bl.stddev())

		// Append CPU sample and prune old ones.
		rm.cpuHist[pid] = append(rm.cpuHist[pid], cpuSample{value: cpuPct, ts: now})
		rm.pruneCPUHist(pid, now, rg.SustainedSeconds*2)
		hist := rm.cpuHist[pid]
		lastCPUAlert := rm.cpuAlert[pid]
		lastMemAlert := rm.memAlert[pid]
		rm.mu.Unlock()

		// Check sustained CPU against adaptive threshold.
		if rm.isSustainedAboveCPU(hist, now, adaptiveThreshold, rg.SustainedSeconds) {
			if time.Since(lastCPUAlert) >= 60*time.Second {
				rm.mu.Lock()
				rm.cpuAlert[pid] = now
				rm.mu.Unlock()

				rm.bus.Publish(event.Event{
					Timestamp: now,
					Source:    "resource",
					Kind:      "cpu_abuse",
					EntityID:  fmt.Sprintf("resource:cpu:%d", pid),
					Details: map[string]any{
						"pid":           pid,
						"name":          name,
						"exe":           exe,
						"cpu_pct":       cpuPct,
						"threshold":     adaptiveThreshold,
						"sustained_sec": rg.SustainedSeconds,
					},
					Message: fmt.Sprintf("CPU abuse: %s (PID %d) %.1f%% > threshold %.1f%% for >%ds",
						name, pid, cpuPct, adaptiveThreshold, rg.SustainedSeconds),
				})
			}
		}

		// Check memory threshold.
		memMB := memInfo.RSS / (1024 * 1024)
		if uint64(memMB) >= rg.MemoryThresholdMB {
			if time.Since(lastMemAlert) >= 60*time.Second {
				rm.mu.Lock()
				rm.memAlert[pid] = now
				rm.mu.Unlock()

				rm.bus.Publish(event.Event{
					Timestamp: now,
					Source:    "resource",
					Kind:      "memory_abuse",
					EntityID:  fmt.Sprintf("resource:mem:%d", pid),
					Details: map[string]any{
						"pid":       pid,
						"name":      name,
						"exe":       exe,
						"memory_mb": memMB,
					},
					Message: fmt.Sprintf("Memory abuse: %s (PID %d) %dMB (limit %dMB)",
						name, pid, memMB, rg.MemoryThresholdMB),
				})
			}
		}
	}

	// Remove handles for processes that no longer exist.
	rm.mu.Lock()
	for pid := range rm.handles {
		if !activePIDs[pid] {
			delete(rm.handles, pid)
			delete(rm.cpuHist, pid)
			delete(rm.cpuAlert, pid)
			delete(rm.memAlert, pid)
		}
	}
	rm.mu.Unlock()
}

// pruneCPUHist removes samples older than maxAgeSec from pid's history.
// Must be called with rm.mu held.
func (rm *ResourceMonitor) pruneCPUHist(pid int32, now time.Time, maxAgeSec int) {
	cutoff := now.Add(-time.Duration(maxAgeSec) * time.Second)
	hist := rm.cpuHist[pid]
	i := 0
	for i < len(hist) && hist[i].ts.Before(cutoff) {
		i++
	}
	rm.cpuHist[pid] = hist[i:]
}

// isSustainedAboveCPU returns true if every sample within the last sustainedSec
// window exceeds threshold, and there are at least 2 samples in that window.
func (rm *ResourceMonitor) isSustainedAboveCPU(hist []cpuSample, now time.Time, threshold float64, sustainedSec int) bool {
	if len(hist) < 2 {
		return false
	}
	cutoff := now.Add(-time.Duration(sustainedSec) * time.Second)

	var windowSamples []cpuSample
	for _, s := range hist {
		if s.ts.After(cutoff) {
			windowSamples = append(windowSamples, s)
		}
	}
	if len(windowSamples) < 2 {
		return false
	}
	for _, s := range windowSamples {
		if s.value < threshold {
			return false
		}
	}
	return true
}

// IsExemptProcess reports whether name matches any pattern in the exempt list.
// Supports trailing-wildcard patterns (e.g., "kworker*").
func IsExemptProcess(name string, exemptList []string) bool {
	for _, ex := range exemptList {
		if strings.HasSuffix(ex, "*") {
			if strings.HasPrefix(name, ex[:len(ex)-1]) {
				return true
			}
		} else if name == ex {
			return true
		}
	}
	return false
}
