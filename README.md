# Noctua

**Real-time cybersecurity automaton agent built in pure Go.**

Monitors processes, network connections, and filesystem changes. Detects threats through behavioral analysis, cross-correlation, machine learning anomaly detection, threat intelligence enrichment, and Sigma rule matching. Escalates through a finite state machine and can auto-block via firewall.

[![CI](https://github.com/KaioH3/noctua/actions/workflows/ci.yml/badge.svg)](https://github.com/KaioH3/noctua/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-333)]()
[![Tests](https://img.shields.io/badge/tests-55%20passed-brightgreen)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()

---

## Why Noctua?

Most host-based security tools are either too simple (just check a port list) or require massive infrastructure (SIEM, ELK, Wazuh). Noctua fills the gap: a **single binary** that runs a full detection pipeline on the host itself, with zero external dependencies.

| What it does | How |
|---|---|
| Detects new/suspicious processes | Scans `/proc` via gopsutil, compares against learned baseline |
| Flags suspicious network activity | Monitors ESTABLISHED connections, tracks C2 ports, connection rates |
| Watches critical files | SHA-256 hashing of `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, etc. |
| Correlates across sources | If same PID has suspicious process + network + filesystem activity, score multiplies |
| Detects unknown threats | Isolation Forest (unsupervised ML) flags statistical outliers |
| Enriches with threat intel | AbuseIPDB reputation, GeoIP location, MalwareBazaar hash lookup, OTX pulses |
| Matches Sigma rules | 20 embedded YAML rules, extensible with custom rules |
| Adapts over time | Feedback loop reduces weight of rules that generate false positives |
| Blocks threats | Optional iptables/pfctl/netsh auto-blocking |

---

## Quick Start

```bash
go build -o noctua ./cmd/noctua/
sudo ./noctua -web
```

The dashboard will be available at **http://localhost:9000** — Noctua prints the URL on startup so you always know where to access it.

```bash
# Skip learning phase (immediate detection)
sudo ./noctua -web -learning 0

# Custom port + firewall auto-block
sudo ./noctua -web -port 8080 -firewall
# Dashboard → http://localhost:8080

# Generate default config file
./noctua -gen-config
```

> Root/sudo is recommended for full process and network visibility.

---

## Detection Pipeline

Every event flows through 7 stages before reaching the FSM:

```
  Monitors (process / network / filesystem)
      |
      v
  1. Heuristic Engine .............. Rule-based scoring (suspicious path, name
      |                              mimicry, C2 ports, critical file mods...)
      v
  2. Cross-Correlator .............. Multi-source correlation per PID
      |                              6 attack pattern detectors
      |                              Score multiplier: 1x / 1.5x / 2.5x
      v
  3. Anomaly Detector .............. Isolation Forest (100 trees, 256 samples)
      |                              Trained on baseline, scores new events
      v
  4. Threat Intel Enrichment ....... AbuseIPDB + GeoIP + MalwareBazaar + OTX
      |                              Cached to disk (24h TTL)
      v
  5. Sigma Rule Engine ............. 20 embedded rules + custom YAML
      |                              Supports contains, startswith, endswith,
      |                              wildcard, regex, AND/OR/NOT, 1-of
      v
  6. Severity Classification ....... INFO < LOW < MEDIUM < HIGH < CRITICAL
      |
      v
  7. FSM Automaton ................. Clean -> Watching -> Suspicious -> Threat -> Blocked
      |                              Score decay over time (5/min)
      |                              Auto-removal after 10min at zero
      v
  Notifier (stdout + logfile + desktop + webhook)
  Dashboard (HTMX + SSE live stream)
  Firewall (iptables / pfctl / netsh)
```

---

## Attack Patterns Detected

The cross-correlator identifies these multi-source attack patterns:

| Pattern | Conditions | Bonus |
|---|---|---|
| **Reverse Shell** | Process from `/tmp/`+`/dev/shm/` + connection to C2 port (4444, 5555, 1337...) | +40 |
| **Data Exfiltration** | Process + network (>20 conn) + filesystem (sensitive file access) | +50 |
| **Persistence** | Process + write to `/etc/crontab`, `/etc/ssh/sshd_config`, `/etc/sudoers` | +35 |
| **Lateral Movement** | Process + SSH (port 22) to private IP range | +45 |
| **Crypto Miner** | Process with high-entropy name + network activity | +40 |
| **Beaconing** | Regular-interval connections (stddev < 15% of mean) to same IP | +55 |

---

## Anomaly Detection

Noctua uses an **Isolation Forest** implemented in pure Go (no cgo, no Python).

During the learning phase, it collects feature vectors per event:

```
[connections/min, unique_dest_IPs, unique_dest_ports, avg_conn_interval, process_creates/min, file_mods/min]
```

After training (100 trees, 256 sample size), any event scoring above the anomaly threshold gets a bonus:

| Anomaly Score | Bonus |
|---|---|
| > 0.95 | +50 |
| > 0.85 | +30 |
| > 0.70 | +15 |

---

## Sigma Rules

20 embedded rules ship with the binary (no external files needed):

| Category | Rules |
|---|---|
| Process | Suspicious path, reverse shell, name mimicry, high-entropy name, crypto miner, enumeration tools, wget/curl from `/tmp`, chmod +x, compiler from `/tmp`, crontab/at |
| Network | C2 ports, IRC, Tor, RDP/VNC outbound, SSH to internal |
| Filesystem | shadow, passwd, sudoers, crontab, sshd_config, hosts |

Add custom rules in `~/.noctua/sigma/` as standard Sigma YAML:

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

Supported modifiers: `contains`, `startswith`, `endswith`, `re` (regex), wildcard (`*`).
Supported conditions: `and`, `or`, `not`, `1 of selection*`, `all of selection*`.

---

## Dashboard

Real-time web UI accessible at **http://localhost:9000** (default port, configurable with `-port`). Uses Server-Sent Events (SSE) for live updates:

- Live event stream with severity badges
- Entity tracking (FSM states, scores)
- Correlation patterns and Sigma rule matches
- Anomaly scores and threat intel indicators
- Uptime, process count, active threats

Built with HTMX + Pico CSS -- lightweight, no npm, no bundler.

---

## API

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/status` | Version, uptime, threat level, component status |
| `GET` | `/api/events` | Recent events (last 500) |
| `GET` | `/api/entities` | All tracked entities with FSM state |
| `GET` | `/api/correlations?pid=N` | Correlation graph (nodes + edges) for a PID |
| `GET` | `/api/intel?ip=X.X.X.X` | Threat intel lookup (AbuseIPDB + GeoIP + OTX) |
| `GET` | `/api/feedback` | Feedback statistics per rule |
| `POST` | `/api/feedback` | Submit false positive: `{"entity_id":"...","rule_name":"...","false_positive":true}` |
| `GET` | `/events/stream` | SSE live event stream |

---

## Configuration

Generate a default config:

```bash
./noctua -gen-config
```

This creates `noctua.json`:

```json
{
  "scan_interval_seconds": 10,
  "learning_period_minutes": 3,
  "thresholds": {
    "watching": 15,
    "suspicious": 35,
    "threat": 65,
    "blocked": 90,
    "decay_per_minute": 5
  },
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
    "sample_size": 256
  },
  "threat_intel": {
    "cache_ttl_minutes": 1440
  }
}
```

### CLI Flags

| Flag | Default | Description |
|---|---|---|
| `-config` | `noctua.json` | Path to config file |
| `-web` | `false` | Enable web dashboard |
| `-port` | `9000` | Dashboard port |
| `-learning` | `3` | Learning period in minutes (0 to skip) |
| `-interval` | `10` | Scan interval in seconds |
| `-firewall` | `false` | Enable auto-blocking via firewall |
| `-no-desktop` | `false` | Disable desktop notifications |
| `-gen-config` | `false` | Generate default config and exit |

### Environment Variables

| Variable | Description |
|---|---|
| `NOCTUA_ABUSEIPDB_KEY` | [AbuseIPDB](https://www.abuseipdb.com/) API key |
| `NOCTUA_OTX_KEY` | [AlienVault OTX](https://otx.alienvault.com/) API key |

GeoIP requires downloading `GeoLite2-City.mmdb` from [MaxMind](https://www.maxmind.com/) to `~/.noctua/GeoLite2-City.mmdb`.

---

## Building

```bash
# Requirements: Go 1.22+

# Build
go build -o noctua ./cmd/noctua/

# Run tests (55 tests)
go test ./...

# Cross-compile
GOOS=windows go build -o noctua.exe ./cmd/noctua/
GOOS=darwin  go build -o noctua-mac ./cmd/noctua/
```

---

## Project Structure

```
cmd/noctua/             CLI entry point
internal/
  agent/                Main orchestrator (pipeline wiring)
  anomaly/              Isolation Forest + feature extraction
  automaton/            Finite state machine (5 states)
  config/               JSON configuration
  correlator/           Cross-correlation graph + 6 attack patterns + beaconing + feedback
  event/                Event struct + pub/sub bus
  firewall/             iptables (Linux), pfctl (macOS), netsh (Windows)
  heuristic/            Rule-based scoring engine
  intel/                AbuseIPDB, GeoIP, MalwareBazaar, OTX
  monitor/              Process, network, filesystem monitors
  notifier/             Desktop, webhook, file logging
  sigma/                Sigma rule loader + matcher + 20 embedded rules
  web/                  Dashboard (HTMX + SSE + Pico CSS)
```

---

## License

MIT
