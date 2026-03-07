package agent

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"noctua/internal/automaton"
	"noctua/internal/config"
	"noctua/internal/event"
	"noctua/internal/firewall"
	"noctua/internal/heuristic"
	"noctua/internal/monitor"
	"noctua/internal/notifier"
)

const maxHistory = 500

type Agent struct {
	cfg      *config.Config
	bus      *event.Bus
	auto     *automaton.Automaton
	engine   *heuristic.Engine
	notifier *notifier.Notifier
	fw       firewall.Firewall

	procMon *monitor.ProcessMonitor
	netMon  *monitor.NetworkMonitor
	fileMon *monitor.FileMonitor

	// state exposed to dashboard
	startTime   time.Time
	history     []event.Event
	historyMu   sync.RWMutex
	sseClients  map[chan event.Event]struct{}
	sseMu       sync.RWMutex
	totalEvents atomic.Int64
	learning    atomic.Bool
}

func New(cfg *config.Config) (*Agent, error) {
	bus := event.NewBus(512)

	noti, err := notifier.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating notifier: %w", err)
	}

	a := &Agent{
		cfg:        cfg,
		bus:        bus,
		auto:       automaton.New(cfg.Thresholds),
		engine:     heuristic.New(),
		notifier:   noti,
		fw:         firewall.New(),
		procMon:    monitor.NewProcessMonitor(bus, cfg),
		netMon:     monitor.NewNetworkMonitor(bus, cfg),
		fileMon:    monitor.NewFileMonitor(bus, cfg),
		startTime:  time.Now(),
		sseClients: make(map[chan event.Event]struct{}),
	}
	a.learning.Store(true)
	return a, nil
}

func (a *Agent) Run(ctx context.Context) error {
	a.printBanner()

	go a.procMon.Run(ctx)
	go a.netMon.Run(ctx)
	go a.fileMon.Run(ctx)
	go a.decayLoop(ctx)
	go a.handleTransitions(ctx)

	fmt.Printf("\033[33m[*] Learning phase: %d minutes (observing baseline)...\033[0m\n",
		a.cfg.LearningPeriodMin)

	select {
	case <-time.After(time.Duration(a.cfg.LearningPeriodMin) * time.Minute):
		a.procMon.SetLearning(false)
		a.netMon.SetLearning(false)
		a.fileMon.SetLearning(false)
		a.learning.Store(false)
		fmt.Printf("\033[32m[+] Learning complete. Baseline: %d processes. Now monitoring.\033[0m\n",
			a.procMon.KnownCount())
	case <-ctx.Done():
		a.cleanup()
		return ctx.Err()
	}

	events := a.bus.Subscribe()
	for {
		select {
		case <-ctx.Done():
			a.cleanup()
			return nil
		case e, ok := <-events:
			if !ok {
				return nil
			}
			a.handleEvent(e)
		}
	}
}

func (a *Agent) handleEvent(e event.Event) {
	a.engine.Score(&e)
	if e.Score <= 0 {
		return
	}

	a.totalEvents.Add(1)
	a.pushHistory(e)
	a.auto.Process(e)
	a.notifier.Notify(e)
	a.broadcastSSE(e)

	if a.cfg.FirewallEnabled {
		ent := a.auto.GetEntity(e.EntityID)
		if ent != nil && ent.State == automaton.Blocked {
			if ip, ok := e.Details["remote_addr"].(string); ok && ip != "" {
				if err := a.fw.BlockIP(ip); err == nil {
					fmt.Printf("\033[1;31m[!] AUTO-BLOCK: %s blocked via firewall\033[0m\n", ip)
				}
			}
		}
	}
}

func (a *Agent) handleTransitions(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case t, ok := <-a.auto.Transitions():
			if !ok {
				return
			}
			a.notifier.NotifyTransition(t.EntityID, t.From.String(), t.To.String(), t.Score)
		}
	}
}

func (a *Agent) decayLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.auto.Decay(30 * time.Second)
		}
	}
}

func (a *Agent) cleanup() {
	a.notifier.Close()
	a.bus.Close()
}

// --- Dashboard Provider methods ---

func (a *Agent) RecentEvents() []event.Event {
	a.historyMu.RLock()
	defer a.historyMu.RUnlock()
	out := make([]event.Event, len(a.history))
	copy(out, a.history)
	// newest first
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (a *Agent) Entities() []automaton.Entity {
	return a.auto.Snapshot()
}

func (a *Agent) SubscribeSSE() (<-chan event.Event, func()) {
	ch := make(chan event.Event, 64)
	a.sseMu.Lock()
	a.sseClients[ch] = struct{}{}
	a.sseMu.Unlock()
	return ch, func() {
		a.sseMu.Lock()
		delete(a.sseClients, ch)
		a.sseMu.Unlock()
	}
}

func (a *Agent) Uptime() time.Duration       { return time.Since(a.startTime) }
func (a *Agent) ProcessCount() int            { return a.procMon.KnownCount() }
func (a *Agent) FilesWatched() int            { return len(a.cfg.WatchedPaths) }
func (a *Agent) TotalEvents() int64           { return a.totalEvents.Load() }
func (a *Agent) IsLearning() bool             { return a.learning.Load() }

func (a *Agent) ThreatLevel() string {
	entities := a.auto.Snapshot()
	max := automaton.Clean
	for _, e := range entities {
		if e.State > max {
			max = e.State
		}
	}
	switch {
	case max >= automaton.Threat:
		return "critical"
	case max >= automaton.Suspicious:
		return "high"
	case max >= automaton.Watching:
		return "elevated"
	default:
		return "safe"
	}
}

func (a *Agent) ActiveThreats() int {
	entities := a.auto.Snapshot()
	n := 0
	for _, e := range entities {
		if e.State >= automaton.Suspicious {
			n++
		}
	}
	return n
}

func (a *Agent) broadcastSSE(e event.Event) {
	a.sseMu.RLock()
	defer a.sseMu.RUnlock()
	for ch := range a.sseClients {
		select {
		case ch <- e:
		default:
		}
	}
}

func (a *Agent) pushHistory(e event.Event) {
	a.historyMu.Lock()
	defer a.historyMu.Unlock()
	a.history = append(a.history, e)
	if len(a.history) > maxHistory {
		a.history = a.history[1:]
	}
}

func (a *Agent) printBanner() {
	fmt.Println("\033[36m")
	fmt.Println(`    _   __           __              `)
	fmt.Println(`   / | / /___  _____/ /___  ______ _ `)
	fmt.Println(`  /  |/ / __ \/ ___/ __/ / / / __ ´/ `)
	fmt.Println(` / /|  / /_/ / /__/ /_/ /_/ / /_/ /  `)
	fmt.Println(`/_/ |_/\____/\___/\__/\__,_/\__,_/   `)
	fmt.Println()
	fmt.Printf(" Cybersecurity Automaton Agent v0.1.0\033[0m\n")
	fmt.Printf(" Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf(" Firewall: %v (enabled=%v)\n", a.fw.Available(), a.cfg.FirewallEnabled)
	fmt.Printf(" Monitors: process, network, filesystem\n")
	fmt.Printf(" Scan interval: %ds\n\n", a.cfg.ScanIntervalSec)
}
