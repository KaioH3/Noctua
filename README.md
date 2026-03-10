# Noctua

**Real-time autonomous cybersecurity agent built in pure Go.**

Monitors processes, network connections, and filesystem changes. Detects threats through behavioral analysis, cross-correlation, machine learning anomaly detection (Isolation Forest with intelligent retraining), threat intelligence enrichment, and Sigma rule matching. Escalates severity through a finite state machine and can auto-block threats via firewall.

> **[Leia em Português](#documentação-em-português)** — Full Portuguese documentation below.

[![CI](https://github.com/KaioH3/noctua/actions/workflows/ci.yml/badge.svg)](https://github.com/KaioH3/noctua/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-333)]()
[![Tests](https://img.shields.io/badge/tests-93%20passed-brightgreen)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()

---

## Why Noctua?

Most host-based security tools are either too simple (just check a port list) or require massive infrastructure (SIEM, ELK, Wazuh). Noctua fills the gap: a **single binary** that runs a full detection pipeline on the host itself, with zero external dependencies.

| What it does | How |
|---|---|
| Detects new/suspicious processes | Scans `/proc` via gopsutil, compares against learned baseline |
| Flags suspicious network activity | Monitors ESTABLISHED connections, tracks C2 ports, connection rates |
| Watches critical files | SHA-256 hashing of `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, etc. |
| Cross-correlates across sources | If same PID has process + network + filesystem activity, score multiplies |
| Detects unknown threats | Isolation Forest (unsupervised ML) flags statistical outliers |
| Automatically retrains | Detects model drift and retrains when system behavior changes |
| Enriches with threat intel | AbuseIPDB reputation, GeoIP location, MalwareBazaar hash lookup, OTX pulses |
| Matches Sigma rules | 20 embedded YAML rules, extensible with custom rules |
| Adapts over time | Feedback loop reduces weight of rules that generate false positives |
| Blocks threats | Optional auto-blocking via iptables/pfctl/netsh |

---

## Quick Start

```bash
# Clone and build
git clone https://github.com/KaioH3/noctua.git
cd noctua
go build -o noctua ./cmd/noctua/

# Generate default config
./noctua --gen-config

# Run with web dashboard
sudo ./noctua --web
# Dashboard → http://localhost:9000
```

That's all you need. Noctua will:
1. Learn normal system behavior for 5 minutes
2. Start monitoring and detecting threats
3. Automatically retrain the anomaly model when system behavior changes

### Stopping Noctua

```bash
# From any terminal:
./noctua --stop

# Or Ctrl+C in the terminal where it's running
```

---

## CLI Reference

```
noctua [flags]
```

| Flag | Short | Default | Description |
|---|---|---|---|
| `--web` | `-w` | `false` | Enable web dashboard |
| `--port` | `-p` | `9000` | Dashboard port |
| `--config` | `-c` | `noctua.json` | Path to config file |
| `--gen-config` | | `false` | Generate default config and exit |
| `--stop` | | `false` | Stop a running instance |

### Examples

```bash
noctua --gen-config              # generate default config
noctua -w                        # dashboard on :9000
noctua -w -p 8080                # dashboard on custom port
noctua -c prod.json -w           # custom config + dashboard
noctua --stop                    # stop running instance
```

> Advanced settings (scan interval, learning period, firewall, desktop notifications, etc.) live in the JSON config file. Generate one with `--gen-config` and edit as needed.

---

## Configuration

Generate the default config:

```bash
./noctua --gen-config
```

This creates `noctua.json`:

```json
{
  "scan_interval_seconds": 10,
  "learning_period_minutes": 5,
  "thresholds": {
    "watching": 15,
    "suspicious": 35,
    "threat": 65,
    "blocked": 90,
    "decay_per_minute": 5
  },
  "watched_paths": [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/group", "/etc/gshadow",
    "/etc/ssh/sshd_config", "/etc/ssh/ssh_config",
    "/etc/crontab", "/etc/cron.d", "/etc/anacrontab",
    "/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf",
    "/etc/rc.local", "/etc/environment", "/etc/profile", "/etc/ld.so.preload",
    "/etc/pam.d", "/etc/iptables", "/etc/nftables.conf"
  ],
  "suspicious_ports": [
    4444, 5555, 6666, 8888, 9999, 1337, 31337,
    6667, 6697,
    3389, 5900, 5901, 5902,
    22,
    4443, 8443, 50050,
    1234, 12345, 54321, 3460, 7777, 9090,
    3333, 14444, 45700,
    1080, 9050, 9150
  ],
  "trusted_processes": [
    "systemd", "init", "kthreadd", "sshd", "cron", "crond",
    "kworker*", "ksoftirqd*", "migration*", "rcu_*",
    "NetworkManager", "wpa_supplicant", "dhclient", "dhcpcd",
    "systemd-resolved", "systemd-networkd", "avahi-daemon",
    "pulseaudio", "pipewire", "pipewire-pulse", "wireplumber",
    "Xorg", "Xwayland", "gnome-shell", "kwin*", "plasmashell",
    "gdm*", "sddm", "lightdm",
    "dbus-daemon", "dbus-broker", "polkitd",
    "apt", "dpkg", "pacman", "dnf", "yum", "zypper", "flatpak",
    "systemd-journald", "rsyslogd", "auditd",
    "udisksd", "upower", "thermald", "irqbalance",
    "accounts-daemon", "colord", "fwupd"
  ],
  "notify_desktop": true,
  "log_file": "noctua.log",
  "firewall_enabled": false,
  "correlator": {
    "enabled": true,
    "time_window_sec": 60,
    "two_source_mult": 1.5,
    "three_source_mult": 2.5
  },
  "anomaly": {
    "enabled": true,
    "num_trees": 100,
    "sample_size": 256,
    "max_buffer": 1000,
    "drift_threshold": 2.0,
    "drift_window_size": 200,
    "fp_rate_threshold": 0.3,
    "check_interval_min": 5
  },
  "threat_intel": {
    "abuseipdb_key": "",
    "geoip_path": "~/.noctua/GeoLite2-City.mmdb",
    "otx_key": "",
    "cache_ttl_minutes": 1440
  },
  "sigma_rules_dir": "~/.noctua/sigma"
}
```

### Config Reference

| Field | Type | Description |
|---|---|---|
| `scan_interval_seconds` | int | Interval between process/network/filesystem scans |
| `learning_period_minutes` | int | Learning phase duration (0 = skip) |
| `thresholds.*` | float | Score thresholds for each FSM state |
| `watched_paths` | []string | Files monitored for changes (SHA-256) |
| `suspicious_ports` | []int | Ports indicating C2 activity |
| `trusted_processes` | []string | Ignored processes (trailing `*` = prefix match) |
| `notify_desktop` | bool | Desktop notifications (notify-send / osascript) |
| `notify_webhook` | string | Webhook URL for alerts (POST JSON) |
| `log_file` | string | Log file path |
| `firewall_enabled` | bool | Auto-block via iptables / pfctl / netsh |
| `anomaly.num_trees` | int | Number of Isolation Forest trees |
| `anomaly.sample_size` | int | Subsample size per tree |
| `anomaly.max_buffer` | int | Circular buffer size for retraining |
| `anomaly.drift_threshold` | float | Std deviations to detect drift (2.0 = 2σ) |
| `anomaly.drift_window_size` | int | Recent scores window for comparison |
| `anomaly.fp_rate_threshold` | float | FP rate that triggers retraining (0.3 = 30%) |
| `anomaly.check_interval_min` | int | Drift check interval (minutes) |

### Environment Variables

| Variable | Description |
|---|---|
| `NOCTUA_ABUSEIPDB_KEY` | [AbuseIPDB](https://www.abuseipdb.com/) API key |
| `NOCTUA_OTX_KEY` | [AlienVault OTX](https://otx.alienvault.com/) API key |

GeoIP requires downloading `GeoLite2-City.mmdb` from [MaxMind](https://www.maxmind.com/) to `~/.noctua/GeoLite2-City.mmdb`.

---

## Detection Pipeline

Every event flows through 7 stages before reaching the FSM:

```
  Monitors (process / network / filesystem)
      │
      ▼
  1. Heuristic Engine .............. Rule-based scoring (suspicious path, name
      │                              mimicry, C2 ports, critical file mods...)
      ▼
  2. Cross-Correlator .............. Multi-source correlation per PID
      │                              6 attack pattern detectors
      │                              Score multiplier: 1x / 1.5x / 2.5x
      ▼
  3. Anomaly Detector .............. Isolation Forest (100 trees, 256 samples)
      │                              Trained on baseline, scores new events
      │                              Auto-retrain via drift detection
      ▼
  4. Threat Intel Enrichment ....... AbuseIPDB + GeoIP + MalwareBazaar + OTX
      │                              Cached to disk (24h TTL)
      ▼
  5. Sigma Rule Engine ............. 20 embedded rules + custom YAML
      │                              Supports contains, startswith, endswith,
      │                              wildcard, regex, AND/OR/NOT, 1-of
      ▼
  6. Severity Classification ....... INFO < LOW < MEDIUM < HIGH < CRITICAL
      │
      ▼
  7. FSM Automaton ................. Clean → Watching → Suspicious → Threat → Blocked
      │                              Score decay over time (5/min)
      │                              Auto-removal after 10min at zero
      ▼
  Notifier (stdout + logfile + desktop + webhook)
  Dashboard (HTMX + SSE live stream)
  Firewall (iptables / pfctl / netsh)
```

---

## Attack Patterns Detected

The cross-correlator identifies these multi-source attack patterns:

| Pattern | Conditions | Bonus |
|---|---|---|
| **Reverse Shell** | Process from `/tmp/` or `/dev/shm/` + connection to C2 port (4444, 5555, 1337...) | +40 |
| **Data Exfiltration** | Process + network (>20 conn) + filesystem (sensitive file access) | +50 |
| **Persistence** | Process + write to `/etc/crontab`, `/etc/ssh/sshd_config`, `/etc/sudoers` | +35 |
| **Lateral Movement** | Process + SSH (port 22) to private IP range | +45 |
| **Crypto Miner** | Process with high-entropy name + network activity | +40 |
| **Beaconing** | Regular-interval connections (stddev < 15% of mean) to same IP | +55 |

---

## Anomaly Detection

Noctua uses an **Isolation Forest** implemented in pure Go (no cgo, no Python).

### Feature Vectors

During the learning phase, it collects 6-dimensional feature vectors per event:

```
[connections/min, unique_dest_IPs, unique_dest_ports, avg_conn_interval, process_creates/min, file_mods/min]
```

### Scoring

After training (100 trees, 256 sample size), events with high anomaly scores get a bonus:

| Anomaly Score | Bonus |
|---|---|
| > 0.95 | +50 |
| > 0.85 | +30 |
| > 0.70 | +15 |

### Intelligent Retraining with Drift Detection

The model doesn't stay static. Two combined metrics decide when to retrain:

**Score Distribution Drift** — Compares recent scores (sliding window of 200) against the original baseline. If the recent mean deviates more than 2σ from baseline, it indicates the model is outdated.

**FP Rate** — Uses user feedback (via API) to compute the false positive rate. If FP rate > 30% (with a minimum of 10 events), triggers retraining.

Retraining is atomic: the new model is trained from the circular buffer (last 1000 samples) without blocking scoring, then swapped in via `atomic.Pointer`. Goroutines calling `Score()` during `Retrain()` keep working without locks.

```
[+] Learning complete. Baseline: 381 processes. Now monitoring.
[*] Drift detection: check every 5m | threshold: 2.0σ | FP rate limit: 30%
    ...
[*] Drift detected (score mean shifted 2.3σ) — retraining anomaly model...
[+] Anomaly model retrained with 847 samples
```

---

## Sigma Rules

20 rules embedded in the binary (no external files needed):

| Category | Rules |
|---|---|
| **Process** | Suspicious path, reverse shell, name mimicry, high-entropy name, crypto miner, enumeration tools, wget/curl from `/tmp`, chmod +x, compiler from `/tmp`, crontab/at |
| **Network** | C2 ports, IRC, Tor, RDP/VNC outbound, SSH to internal |
| **Filesystem** | shadow, passwd, sudoers, crontab, sshd_config, hosts |

### Custom Rules

Add Sigma rules to `~/.noctua/sigma/` as standard YAML:

```yaml
title: My Custom Rule
level: high
logsource:
  category: process_creation
detection:
  selection:
    Image|contains: '/suspicious/path'
  condition: selection
```

**Supported modifiers:** `contains`, `startswith`, `endswith`, `re` (regex), wildcard (`*`).

**Supported conditions:** `and`, `or`, `not`, `1 of selection*`, `all of selection*`.

---

## Dashboard

Real-time web UI at **http://localhost:9000** (configurable with `-p`). Uses Server-Sent Events (SSE) for live updates.

Features:
- Live event stream with severity badges
- Entity tracking (FSM states, scores, last activity)
- Anomaly detection and threat intel indicators
- Uptime, process count, active threats, global threat level
- Sigma rule count

Built with HTMX + Pico CSS — lightweight, no npm, no bundler.

---

## API

All endpoints return JSON.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/status` | Version, uptime, threat level, component status |
| `GET` | `/api/events` | Recent events (last 500) |
| `GET` | `/api/entities` | All tracked entities with FSM state |
| `GET` | `/api/correlations?pid=N` | Correlation graph (nodes + edges) for a PID |
| `GET` | `/api/intel?ip=X.X.X.X` | Threat intel lookup (AbuseIPDB + GeoIP + OTX) |
| `GET` | `/api/feedback` | Feedback statistics per rule |
| `POST` | `/api/feedback` | Submit false positive (see example below) |
| `GET` | `/events/stream` | SSE live event stream |

### Examples

```bash
# Report false positive
curl -X POST http://localhost:9000/api/feedback \
  -H 'Content-Type: application/json' \
  -d '{"entity_id":"proc:12345:curl","rule_name":"suspicious_path","false_positive":true}'

# Check system status
curl -s http://localhost:9000/api/status | python3 -m json.tool

# Stream live events
curl -N http://localhost:9000/events/stream
```

---

## Trusted Processes

Noctua ignores processes listed in `trusted_processes`. Supports wildcard prefix matching with trailing `*`:

```json
{
  "trusted_processes": [
    "systemd",         "exact match only"
    "kworker*",        "prefix: matches kworker/3:2-events, kworker/u48:0-iou_exit, etc."
    "my-daemon*"       "prefix: matches anything starting with my-daemon"
  ]
}
```

`kworker*` is included by default to filter kernel worker threads that generate noise.

---

## Finite State Machine (FSM)

Each entity (process, network connection, IP) is tracked by a 5-state FSM:

```
Clean ──→ Watching ──→ Suspicious ──→ Threat ──→ Blocked
  ↑          │             │            │
  └──────────┴─────────────┴────────────┘
              (score decay over time)
```

| State | Min Score | Meaning |
|---|---|---|
| **Clean** | 0 | Normal behavior |
| **Watching** | 15 | Slightly anomalous, monitoring |
| **Suspicious** | 35 | Concerning pattern, investigate |
| **Threat** | 65 | Confirmed threat |
| **Blocked** | 90 | Threat blocked (if firewall enabled) |

Score decays at 5 points per minute. Entities return to Clean when score reaches zero.

---

## Building & Testing

```bash
# Requirements: Go 1.22+

# Build
go build -o noctua ./cmd/noctua/

# Run all tests (93 tests)
go test ./...

# Verbose tests for a specific package
go test -v ./internal/anomaly/

# Cross-compile
GOOS=windows go build -o noctua.exe ./cmd/noctua/
GOOS=darwin  go build -o noctua-mac ./cmd/noctua/
```

### Test Coverage by Package

| Package | Tests | Coverage |
|---|---|---|
| `anomaly` | 21 | Isolation Forest, feature extraction, drift detection, atomic retrain, E2E |
| `correlator` | 27 | Correlation graph, 6 attack patterns, beaconing, feedback |
| `sigma` | 20 | YAML loader, condition matcher, modifiers, embedded rules |
| `automaton` | 12 | FSM transitions, decay, entity tracking |
| `heuristic` | 9 | Rule-based scoring, severity classification |
| `event` | 4 | Pub/sub bus, subscribe/publish |

---

## Project Structure

```
noctua/
├── cmd/noctua/                CLI entry point (pflag, PID file, --stop)
├── internal/
│   ├── agent/                 Main orchestrator (pipeline wiring, drift check loop)
│   ├── anomaly/               Isolation Forest + feature extraction + drift monitor
│   │   ├── detector.go        Detector with circular buffer, atomic pointer, retrain
│   │   ├── drift.go           DriftMonitor (sliding window, shift detection)
│   │   ├── features.go        Feature vector extractor (6 dimensions)
│   │   ├── iforest.go         Pure Isolation Forest (fit, score, subsample)
│   │   ├── drift_test.go      Drift detection tests
│   │   ├── detector_test.go   Detector tests (retrain, atomic swap)
│   │   └── e2e_test.go        End-to-end test: train → drift → retrain
│   ├── automaton/             Finite state machine (5 states)
│   ├── config/                JSON configuration with sensible defaults
│   ├── correlator/            Correlation graph + 6 attack patterns + beaconing + feedback
│   ├── event/                 Event struct + pub/sub bus
│   ├── firewall/              iptables (Linux), pfctl (macOS), netsh (Windows)
│   ├── heuristic/             Rule-based scoring engine
│   ├── intel/                 AbuseIPDB, GeoIP, MalwareBazaar, OTX
│   ├── monitor/               Process, network, filesystem monitors
│   ├── notifier/              Desktop (notify-send), webhook, file logging
│   ├── sigma/                 Sigma rule loader + matcher + 20 embedded rules
│   └── web/                   Dashboard (HTMX + SSE + Pico CSS)
├── noctua.json                Configuration (generated with --gen-config)
├── go.mod
└── go.sum
```

**44 Go files | ~6700 lines | 93 tests**

---

---

# Documentação em Português

Agente autônomo de cibersegurança em Go puro. Monitora processos, rede e filesystem em tempo real. Detecta ameaças via análise comportamental, correlação cruzada, ML (Isolation Forest com retreino automático), threat intel e regras Sigma.

## Início Rápido

```bash
git clone https://github.com/KaioH3/noctua.git && cd noctua
go build -o noctua ./cmd/noctua/
./noctua --gen-config
sudo ./noctua --web    # Dashboard → http://localhost:9000
```

## Pipeline

```
Monitores → Heurísticas → Correlação → Anomaly (IF) → Threat Intel → Sigma → FSM → Ação
```

## Stack

| Componente | Detalhe |
|---|---|
| Linguagem | Go 1.23+ (zero cgo) |
| ML | Isolation Forest puro com drift detection e retreino atômico |
| Threat Intel | AbuseIPDB, GeoIP, MalwareBazaar, OTX |
| Regras | 20 Sigma embarcadas + customizadas |
| Dashboard | HTMX + SSE + Pico CSS |
| Firewall | iptables / pfctl / netsh |

## Testes

93 testes — `go test ./...`

## Licença

MIT
