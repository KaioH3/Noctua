package agent

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"noctua/internal/automaton"
	"noctua/internal/config"
	"noctua/internal/event"
	"noctua/internal/firewall"
	"noctua/internal/heuristic"
	"noctua/internal/monitor"
	"noctua/internal/notifier"
)

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
}

func New(cfg *config.Config) (*Agent, error) {
	bus := event.NewBus(512)

	noti, err := notifier.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating notifier: %w", err)
	}

	return &Agent{
		cfg:      cfg,
		bus:      bus,
		auto:     automaton.New(cfg.Thresholds),
		engine:   heuristic.New(),
		notifier: noti,
		fw:       firewall.New(),
		procMon:  monitor.NewProcessMonitor(bus, cfg),
		netMon:   monitor.NewNetworkMonitor(bus, cfg),
		fileMon:  monitor.NewFileMonitor(bus, cfg),
	}, nil
}

func (a *Agent) Run(ctx context.Context) error {
	a.printBanner()

	// start monitors
	go a.procMon.Run(ctx)
	go a.netMon.Run(ctx)
	go a.fileMon.Run(ctx)

	// start decay ticker
	go a.decayLoop(ctx)

	// start transition handler
	go a.handleTransitions(ctx)

	// learning phase
	fmt.Printf("\033[33m[*] Learning phase: %d minutes (observing baseline)...\033[0m\n",
		a.cfg.LearningPeriodMin)

	select {
	case <-time.After(time.Duration(a.cfg.LearningPeriodMin) * time.Minute):
		a.procMon.SetLearning(false)
		a.netMon.SetLearning(false)
		a.fileMon.SetLearning(false)
		fmt.Printf("\033[32m[+] Learning complete. Baseline: %d processes. Now monitoring.\033[0m\n",
			a.procMon.KnownCount())
	case <-ctx.Done():
		a.cleanup()
		return ctx.Err()
	}

	// main event loop
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
	// score the event
	a.engine.Score(&e)

	// skip noise
	if e.Score <= 0 {
		return
	}

	// feed to automaton
	a.auto.Process(e)

	// notify
	a.notifier.Notify(e)

	// auto-block if configured and entity reaches blocked state
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
	transitions := a.auto.Transitions()
	for {
		select {
		case <-ctx.Done():
			return
		case t, ok := <-transitions:
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
