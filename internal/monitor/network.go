package monitor

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/net"

	"noctua/internal/config"
	"noctua/internal/event"
)

type connKey struct {
	LocalPort  uint32
	RemoteAddr string
	RemotePort uint32
	PID        int32
}

type NetworkMonitor struct {
	bus      *event.Bus
	cfg      *config.Config
	known    map[connKey]time.Time
	mu       sync.Mutex
	learning bool

	// rate tracking per PID
	connCounts map[int32]int
	lastReset  time.Time
}

func NewNetworkMonitor(bus *event.Bus, cfg *config.Config) *NetworkMonitor {
	return &NetworkMonitor{
		bus:        bus,
		cfg:        cfg,
		known:      make(map[connKey]time.Time),
		connCounts: make(map[int32]int),
		lastReset:  time.Now(),
		learning:   true,
	}
}

func (nm *NetworkMonitor) SetLearning(v bool) {
	nm.mu.Lock()
	nm.learning = v
	nm.mu.Unlock()
}

func (nm *NetworkMonitor) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(nm.cfg.ScanIntervalSec) * time.Second)
	defer ticker.Stop()

	nm.scan()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			nm.scan()
		}
	}
}

func (nm *NetworkMonitor) scan() {
	conns, err := net.Connections("inet")
	if err != nil {
		return
	}

	nm.mu.Lock()
	learning := nm.learning

	// reset rate counter every minute
	if time.Since(nm.lastReset) > time.Minute {
		nm.connCounts = make(map[int32]int)
		nm.lastReset = time.Now()
	}
	nm.mu.Unlock()

	current := make(map[connKey]bool, len(conns))
	now := time.Now()

	for _, c := range conns {
		if c.Status != "ESTABLISHED" && c.Status != "SYN_SENT" {
			continue
		}

		// skip loopback
		if c.Raddr.IP == "127.0.0.1" || c.Raddr.IP == "::1" || c.Raddr.IP == "" {
			continue
		}

		key := connKey{
			LocalPort:  c.Laddr.Port,
			RemoteAddr: c.Raddr.IP,
			RemotePort: c.Raddr.Port,
			PID:        c.Pid,
		}
		current[key] = true

		nm.mu.Lock()
		_, exists := nm.known[key]
		nm.known[key] = now
		nm.connCounts[c.Pid]++
		connCount := nm.connCounts[c.Pid]
		nm.mu.Unlock()

		if exists || learning {
			continue
		}

		// check for suspicious remote port
		if nm.isSuspiciousPort(c.Raddr.Port) {
			nm.bus.Publish(event.Event{
				Timestamp: now,
				Source:    "network",
				Kind:     "suspicious_port",
				EntityID:  fmt.Sprintf("net:%s:%d", c.Raddr.IP, c.Raddr.Port),
				Details: map[string]any{
					"pid":         c.Pid,
					"remote_addr": c.Raddr.IP,
					"remote_port": c.Raddr.Port,
					"local_port":  c.Laddr.Port,
				},
				Message: fmt.Sprintf("Suspicious port: PID %d → %s:%d",
					c.Pid, c.Raddr.IP, c.Raddr.Port),
			})
			continue
		}

		// check for high connection rate
		if connCount > 20 {
			nm.bus.Publish(event.Event{
				Timestamp: now,
				Source:    "network",
				Kind:     "high_conn_rate",
				EntityID:  fmt.Sprintf("net:rate:%d", c.Pid),
				Details: map[string]any{
					"pid":   c.Pid,
					"count": connCount,
				},
				Message: fmt.Sprintf("High connection rate: PID %d has %d connections/min",
					c.Pid, connCount),
			})
			continue
		}

		// new outbound connection
		nm.bus.Publish(event.Event{
			Timestamp: now,
			Source:    "network",
			Kind:     "new_outbound",
			EntityID:  fmt.Sprintf("net:%s:%d", c.Raddr.IP, c.Raddr.Port),
			Details: map[string]any{
				"pid":         c.Pid,
				"remote_addr": c.Raddr.IP,
				"remote_port": c.Raddr.Port,
			},
			Message: fmt.Sprintf("New outbound: PID %d → %s:%d",
				c.Pid, c.Raddr.IP, c.Raddr.Port),
		})
	}

	// cleanup stale connections
	nm.mu.Lock()
	for key := range nm.known {
		if !current[key] {
			delete(nm.known, key)
		}
	}
	nm.mu.Unlock()
}

func (nm *NetworkMonitor) isSuspiciousPort(port uint32) bool {
	for _, p := range nm.cfg.SuspiciousPorts {
		if port == p {
			return true
		}
	}
	return false
}
