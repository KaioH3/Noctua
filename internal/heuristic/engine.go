package heuristic

import (
	"math"
	"strings"

	"noctua/internal/event"
)

type Rule struct {
	Name     string
	Source   string // "process", "network", "filesystem", "" = all
	Evaluate func(e *event.Event) float64
}

type Engine struct {
	rules []Rule
}

func New() *Engine {
	eng := &Engine{}
	eng.registerProcessRules()
	eng.registerNetworkRules()
	eng.registerFilesystemRules()
	eng.registerResourceRules()
	return eng
}

func (eng *Engine) Score(e *event.Event) float64 {
	var total float64
	for _, r := range eng.rules {
		if r.Source != "" && r.Source != e.Source {
			continue
		}
		total += r.Evaluate(e)
	}
	e.Score = total
	e.Severity = ClassifySeverity(total)
	return total
}

func ClassifySeverity(score float64) event.Severity {
	switch {
	case score >= 70:
		return event.Critical
	case score >= 50:
		return event.High
	case score >= 30:
		return event.Medium
	case score >= 15:
		return event.Low
	default:
		return event.Info
	}
}

// --- Process Rules ---

func (eng *Engine) registerProcessRules() {
	eng.rules = append(eng.rules,
		Rule{
			Name:   "suspicious_path",
			Source: "process",
			Evaluate: func(e *event.Event) float64 {
				exe, _ := e.Details["exe"].(string)
				suspicious := []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/.cache/", "/Downloads/"}
				for _, p := range suspicious {
					if strings.Contains(exe, p) {
						return 30
					}
				}
				return 0
			},
		},
		Rule{
			Name:   "name_mimicry",
			Source: "process",
			Evaluate: func(e *event.Event) float64 {
				name, _ := e.Details["name"].(string)
				exe, _ := e.Details["exe"].(string)
				// System process names running from wrong paths
				systemNames := map[string]string{
					"sshd":    "/usr/sbin/",
					"systemd": "/usr/lib/systemd/",
					"cron":    "/usr/sbin/",
					"init":    "/sbin/",
				}
				if expectedPath, ok := systemNames[name]; ok {
					if !strings.HasPrefix(exe, expectedPath) && exe != "" {
						return 50
					}
				}
				return 0
			},
		},
		Rule{
			Name:   "unusual_hour",
			Source: "process",
			Evaluate: func(e *event.Event) float64 {
				hour := e.Timestamp.Hour()
				if hour >= 2 && hour <= 5 {
					return 10
				}
				return 0
			},
		},
		Rule{
			Name:   "privilege_escalation",
			Source: "process",
			Evaluate: func(e *event.Event) float64 {
				name, _ := e.Details["name"].(string)
				exe, _ := e.Details["exe"].(string)
				// su/sudo spawned from unexpected parent context
				privTools := []string{"su", "sudo", "pkexec", "runuser", "newgrp"}
				for _, t := range privTools {
					if name == t || strings.HasSuffix(exe, "/"+t) {
						return 20
					}
				}
				return 0
			},
		},
		Rule{
			Name:   "scripting_from_temp",
			Source: "process",
			Evaluate: func(e *event.Event) float64 {
				exe, _ := e.Details["exe"].(string)
				name, _ := e.Details["name"].(string)
				scripts := []string{"bash", "sh", "python", "python3", "perl", "ruby", "node"}
				tempPaths := []string{"/tmp/", "/var/tmp/", "/dev/shm/"}
				for _, s := range scripts {
					if name != s {
						continue
					}
					for _, p := range tempPaths {
						if strings.Contains(exe, p) {
							return 35
						}
					}
				}
				return 0
			},
		},
		Rule{
			Name:   "high_entropy_name",
			Source: "process",
			Evaluate: func(e *event.Event) float64 {
				name, _ := e.Details["name"].(string)
				if len(name) > 8 && entropy(name) > 3.5 {
					return 20
				}
				return 0
			},
		},
	)
}

// --- Network Rules ---

func (eng *Engine) registerNetworkRules() {
	eng.rules = append(eng.rules,
		Rule{
			Name:   "suspicious_port",
			Source: "network",
			Evaluate: func(e *event.Event) float64 {
				if e.Kind == "suspicious_port" {
					return 25
				}
				return 0
			},
		},
		Rule{
			Name:   "high_connection_rate",
			Source: "network",
			Evaluate: func(e *event.Event) float64 {
				if e.Kind == "high_conn_rate" {
					count, _ := e.Details["count"].(int)
					if count > 50 {
						return 40
					}
					if count > 20 {
						return 20
					}
				}
				return 0
			},
		},
		Rule{
			Name:   "outbound_unusual",
			Source: "network",
			Evaluate: func(e *event.Event) float64 {
				if e.Kind == "new_outbound" {
					return 5 // baseline score for any new outbound
				}
				return 0
			},
		},
		Rule{
			Name:   "port_scan",
			Source: "network",
			Evaluate: func(e *event.Event) float64 {
				if e.Kind == "port_scan" {
					ports, _ := e.Details["unique_ports"].(int)
					if ports > 50 {
						return 70
					}
					if ports > 20 {
						return 45
					}
				}
				return 0
			},
		},
	)
}

// --- Filesystem Rules ---

func (eng *Engine) registerFilesystemRules() {
	eng.rules = append(eng.rules,
		Rule{
			Name:   "critical_file_modified",
			Source: "filesystem",
			Evaluate: func(e *event.Event) float64 {
				if e.Kind == "file_modified" {
					path, _ := e.Details["path"].(string)
					critical := []string{"/etc/shadow", "/etc/passwd", "/etc/sudoers"}
					for _, c := range critical {
						if path == c {
							return 60
						}
					}
					return 30
				}
				return 0
			},
		},
		Rule{
			Name:   "rapid_modifications",
			Source: "filesystem",
			Evaluate: func(e *event.Event) float64 {
				if e.Kind == "rapid_changes" {
					count, _ := e.Details["count"].(int)
					if count > 10 {
						return 70 // possible ransomware
					}
				}
				return 0
			},
		},
	)
}

// --- Resource Rules ---

func (eng *Engine) registerResourceRules() {
	eng.rules = append(eng.rules,
		Rule{
			Name:   "cpu_abuse",
			Source: "resource",
			Evaluate: func(e *event.Event) float64 {
				if e.Kind == "cpu_abuse" {
					cpuPct, _ := e.Details["cpu_pct"].(float64)
					if cpuPct >= 95 {
						return 50
					}
					return 40
				}
				return 0
			},
		},
		Rule{
			Name:   "memory_abuse",
			Source: "resource",
			Evaluate: func(e *event.Event) float64 {
				if e.Kind == "memory_abuse" {
					return 30
				}
				return 0
			},
		},
		Rule{
			Name:   "spawn_loop",
			Source: "process",
			Evaluate: func(e *event.Event) float64 {
				if e.Kind == "spawn_loop" {
					count, _ := e.Details["child_count"].(int)
					if count > 20 {
						return 60
					}
					return 50
				}
				return 0
			},
		},
	)
}

// Shannon entropy of a string — high entropy = random/encoded names
func entropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	length := float64(len([]rune(s)))
	var ent float64
	for _, count := range freq {
		p := count / length
		if p > 0 {
			ent -= p * math.Log2(p)
		}
	}
	return ent
}
