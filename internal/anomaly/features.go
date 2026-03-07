package anomaly

import (
	"sync"
	"time"

	"noctua/internal/event"
)

type pidMetrics struct {
	ConnectionCount int
	UniqueDestIPs   map[string]bool
	UniqueDestPorts map[uint32]bool
	ConnTimes       []time.Time
}

type FeatureExtractor struct {
	mu          sync.Mutex
	pidMetrics  map[int32]*pidMetrics
	procCreates []time.Time
	fileMods    []time.Time
	window      time.Duration
}

func NewFeatureExtractor() *FeatureExtractor {
	return &FeatureExtractor{
		pidMetrics: make(map[int32]*pidMetrics),
		window:     5 * time.Minute,
	}
}

func (fe *FeatureExtractor) Extract(e event.Event) []float64 {
	fe.mu.Lock()
	defer fe.mu.Unlock()

	now := e.Timestamp
	fe.pruneOld(now)

	pid := extractPID(e)

	switch e.Source {
	case "process":
		fe.procCreates = append(fe.procCreates, now)
	case "network":
		m := fe.getOrCreatePID(pid)
		m.ConnectionCount++
		m.ConnTimes = append(m.ConnTimes, now)
		if addr, ok := e.Details["remote_addr"].(string); ok {
			m.UniqueDestIPs[addr] = true
		}
		if port, ok := e.Details["remote_port"].(uint32); ok {
			m.UniqueDestPorts[port] = true
		} else if portF, ok := e.Details["remote_port"].(float64); ok {
			m.UniqueDestPorts[uint32(portF)] = true
		}
	case "filesystem":
		fe.fileMods = append(fe.fileMods, now)
	}

	// Build feature vector
	// [conn_count/min, unique_ips, unique_ports, avg_interval, proc_creates/min, file_mods/min]
	m := fe.getOrCreatePID(pid)
	windowMin := fe.window.Minutes()

	connPerMin := float64(m.ConnectionCount) / windowMin
	uniqueIPs := float64(len(m.UniqueDestIPs))
	uniquePorts := float64(len(m.UniqueDestPorts))
	avgInterval := fe.avgConnInterval(m)
	procPerMin := float64(len(fe.procCreates)) / windowMin
	fileModPerMin := float64(len(fe.fileMods)) / windowMin

	return []float64{connPerMin, uniqueIPs, uniquePorts, avgInterval, procPerMin, fileModPerMin}
}

func (fe *FeatureExtractor) getOrCreatePID(pid int32) *pidMetrics {
	m, ok := fe.pidMetrics[pid]
	if !ok {
		m = &pidMetrics{
			UniqueDestIPs:   make(map[string]bool),
			UniqueDestPorts: make(map[uint32]bool),
		}
		fe.pidMetrics[pid] = m
	}
	return m
}

func (fe *FeatureExtractor) avgConnInterval(m *pidMetrics) float64 {
	if len(m.ConnTimes) < 2 {
		return 0
	}
	var total float64
	for i := 1; i < len(m.ConnTimes); i++ {
		total += m.ConnTimes[i].Sub(m.ConnTimes[i-1]).Seconds()
	}
	return total / float64(len(m.ConnTimes)-1)
}

func (fe *FeatureExtractor) pruneOld(now time.Time) {
	cutoff := now.Add(-fe.window)

	fe.procCreates = filterTimes(fe.procCreates, cutoff)
	fe.fileMods = filterTimes(fe.fileMods, cutoff)

	for pid, m := range fe.pidMetrics {
		m.ConnTimes = filterTimes(m.ConnTimes, cutoff)
		if len(m.ConnTimes) == 0 {
			delete(fe.pidMetrics, pid)
		}
	}
}

func filterTimes(times []time.Time, cutoff time.Time) []time.Time {
	var result []time.Time
	for _, t := range times {
		if t.After(cutoff) {
			result = append(result, t)
		}
	}
	return result
}

func extractPID(e event.Event) int32 {
	switch v := e.Details["pid"].(type) {
	case int32:
		return v
	case int:
		return int32(v)
	case int64:
		return int32(v)
	case float64:
		return int32(v)
	default:
		return 0
	}
}
