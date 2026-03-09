package agent

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"os"

	"noctua/internal/anomaly"
	"noctua/internal/automaton"
	"noctua/internal/config"
	"noctua/internal/correlator"
	"noctua/internal/event"
	"noctua/internal/firewall"
	"noctua/internal/heuristic"
	"noctua/internal/intel"
	"noctua/internal/monitor"
	"noctua/internal/notifier"
	"noctua/internal/sigma"
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

	// v0.2.0 components
	corr         *correlator.Correlator
	anomaly      *anomaly.Detector
	enricher     *intel.Enricher
	sigmaEngine  *sigma.Engine
	feedback     *correlator.FeedbackStore
	sigmaTmpDir  string

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
		feedback:   correlator.NewFeedbackStore(),
		startTime:  time.Now(),
		sseClients: make(map[chan event.Event]struct{}),
	}
	a.learning.Store(true)

	// Initialize correlator
	if cfg.Correlator.Enabled {
		a.corr = correlator.New(
			cfg.Correlator.TimeWindowSec,
			cfg.Correlator.TwoSourceMult,
			cfg.Correlator.ThreeSourceMult,
		)
	}

	// Initialize anomaly detector
	if cfg.Anomaly.Enabled {
		a.anomaly = anomaly.NewDetector(
			cfg.Anomaly.NumTrees,
			cfg.Anomaly.SampleSize,
			cfg.Anomaly.MaxBuffer,
			cfg.Anomaly.DriftWindowSize,
			cfg.Anomaly.DriftThreshold,
		)
	}

	// Initialize threat intel enricher
	a.enricher = intel.NewEnricher(cfg.ThreatIntel.CacheTTLMinutes)

	if cfg.ThreatIntel.AbuseIPDBKey != "" {
		a.enricher.AddProvider(intel.NewAbuseIPDB(cfg.ThreatIntel.AbuseIPDBKey))
	}
	if cfg.ThreatIntel.OTXKey != "" {
		a.enricher.AddProvider(intel.NewOTX(cfg.ThreatIntel.OTXKey))
	}
	if cfg.ThreatIntel.GeoIPPath != "" {
		if geoip, err := intel.NewGeoIP(cfg.ThreatIntel.GeoIPPath); err == nil {
			a.enricher.AddProvider(geoip)
		}
	}
	a.enricher.AddHashProvider(intel.NewMalwareBazaar())

	// Initialize Sigma rules
	a.initSigma()

	return a, nil
}

func (a *Agent) initSigma() {
	var ruleDirs []string

	// Extract embedded rules to temp dir
	if tmpDir, err := sigma.ExtractEmbeddedRules(); err == nil {
		a.sigmaTmpDir = tmpDir
		ruleDirs = append(ruleDirs, tmpDir)
	}

	// Add user sigma rules dir
	if a.cfg.SigmaRulesDir != "" {
		ruleDirs = append(ruleDirs, a.cfg.SigmaRulesDir)
	}

	rules, _ := sigma.LoadRules(ruleDirs...)
	a.sigmaEngine = sigma.NewEngine(rules)

	if len(rules) > 0 {
		fmt.Printf(" Sigma rules: %d loaded\n", len(rules))
	}
}

func (a *Agent) Run(ctx context.Context) error {
	a.printBanner()

	go a.procMon.Run(ctx)
	go a.netMon.Run(ctx)
	go a.fileMon.Run(ctx)
	go a.decayLoop(ctx)
	go a.handleTransitions(ctx)

	if a.corr != nil {
		go a.corr.StartPruning(ctx)
	}

	fmt.Printf("\033[33m[*] Learning phase: %d minutes (observing baseline)...\033[0m\n",
		a.cfg.LearningPeriodMin)

	select {
	case <-time.After(time.Duration(a.cfg.LearningPeriodMin) * time.Minute):
		a.procMon.SetLearning(false)
		a.netMon.SetLearning(false)
		a.fileMon.SetLearning(false)
		a.learning.Store(false)

		// Train anomaly detector after learning phase
		if a.anomaly != nil {
			a.anomaly.Train()
		}

		fmt.Printf("\033[32m[+] Learning complete. Baseline: %d processes. Now monitoring.\033[0m\n",
			a.procMon.KnownCount())

		if a.anomaly != nil && a.cfg.Anomaly.CheckIntervalMin > 0 {
			fmt.Printf("\033[36m[*] Drift detection: check every %dm | threshold: %.1fσ | FP rate limit: %.0f%%\033[0m\n",
				a.cfg.Anomaly.CheckIntervalMin, a.cfg.Anomaly.DriftThreshold, a.cfg.Anomaly.FPRateThreshold*100)
			go a.driftCheckLoop(ctx)
		}
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
	// 1. Rule-based scoring
	a.engine.Score(&e)
	if e.Score <= 0 {
		return
	}

	// 2. Cross-correlation + multiplier
	if a.corr != nil {
		a.corr.Correlate(&e)
	}

	// 3. Anomaly detection bonus
	if a.anomaly != nil {
		a.anomaly.Evaluate(&e)
	}

	// 4. Threat intel enrichment
	if a.enricher != nil {
		a.enricher.Enrich(&e)
	}

	// 5. Sigma rule matching
	if a.sigmaEngine != nil {
		a.sigmaEngine.Evaluate(&e)
	}

	// 6. Final severity based on total score
	e.Severity = heuristic.ClassifySeverity(e.Score)

	a.totalEvents.Add(1)
	a.pushHistory(e)

	// 7. FSM state tracking
	a.auto.Process(e)

	// 8. Alerts
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
	if a.sigmaTmpDir != "" {
		os.RemoveAll(a.sigmaTmpDir)
	}
}

func (a *Agent) driftCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(a.cfg.Anomaly.CheckIntervalMin) * time.Minute)
	defer ticker.Stop()

	var lastFPRetrain time.Time
	// Suppress FP-triggered retrains for 3x the check interval,
	// since FP rate data doesn't change from retraining alone.
	fpCooldown := time.Duration(a.cfg.Anomaly.CheckIntervalMin) * time.Minute * 3

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			drifted := a.anomaly.NeedsRetrain()
			fpExceeded := a.fpRateExceeded() && time.Since(lastFPRetrain) > fpCooldown

			if !drifted && !fpExceeded {
				continue
			}

			var reasons []string
			if drifted {
				reasons = append(reasons, fmt.Sprintf("score mean shifted %.1fσ", a.anomaly.DriftMagnitude()))
			}
			if fpExceeded {
				reasons = append(reasons, fmt.Sprintf("FP rate %.0f%%", a.fpRate()*100))
			}

			reason := reasons[0]
			if len(reasons) > 1 {
				reason = reasons[0] + " + " + reasons[1]
			}

			fmt.Printf("\033[33m[*] Drift detected (%s) — retraining anomaly model...\033[0m\n", reason)
			n := a.anomaly.Retrain()
			if n > 0 {
				fmt.Printf("\033[32m[+] Anomaly model retrained with %d samples\033[0m\n", n)
			}

			if fpExceeded {
				lastFPRetrain = time.Now()
			}
		}
	}
}

const minFPEvents = 10 // need at least 10 feedback events before FP rate is meaningful

func (a *Agent) fpRate() float64 {
	stats := a.feedback.Stats()
	var totalFP, totalEvents int
	for _, entry := range stats {
		totalFP += entry.FalsePositives
		totalEvents += entry.TotalEvents
	}
	if totalEvents == 0 {
		return 0
	}
	return float64(totalFP) / float64(totalEvents)
}

func (a *Agent) fpRateExceeded() bool {
	stats := a.feedback.Stats()
	var totalFP, totalEvents int
	for _, entry := range stats {
		totalFP += entry.FalsePositives
		totalEvents += entry.TotalEvents
	}
	if totalEvents < minFPEvents {
		return false
	}
	fpRate := float64(totalFP) / float64(totalEvents)
	return fpRate > a.cfg.Anomaly.FPRateThreshold
}

// --- Dashboard Provider methods ---

func (a *Agent) RecentEvents() []event.Event {
	a.historyMu.RLock()
	defer a.historyMu.RUnlock()
	out := make([]event.Event, len(a.history))
	copy(out, a.history)
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

func (a *Agent) CorrelationGraph(pid int32) correlator.GraphSnapshot {
	if a.corr != nil {
		return a.corr.GraphForPID(pid)
	}
	return correlator.GraphSnapshot{}
}

func (a *Agent) IntelLookup(ip string) map[string]any {
	if a.enricher != nil {
		return a.enricher.LookupIP(ip)
	}
	return nil
}

func (a *Agent) RecordFeedback(entityID, ruleName string, isFalsePositive bool) {
	a.feedback.RecordFeedback(entityID, ruleName, isFalsePositive)
}

func (a *Agent) FeedbackStats() map[string]*correlator.FeedbackEntry {
	return a.feedback.Stats()
}

func (a *Agent) AnomalyTrained() bool {
	if a.anomaly != nil {
		return a.anomaly.IsTrained()
	}
	return false
}

func (a *Agent) SigmaRuleCount() int {
	if a.sigmaEngine != nil {
		return a.sigmaEngine.RuleCount()
	}
	return 0
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
	fmt.Printf(" Cybersecurity Automaton Agent v0.2.0\033[0m\n")
	fmt.Printf(" Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf(" Firewall: %v (enabled=%v)\n", a.fw.Available(), a.cfg.FirewallEnabled)
	fmt.Printf(" Monitors: process, network, filesystem\n")
	fmt.Printf(" Correlator: %v | Anomaly: %v\n", a.cfg.Correlator.Enabled, a.cfg.Anomaly.Enabled)
	fmt.Printf(" Scan interval: %ds\n\n", a.cfg.ScanIntervalSec)
}
