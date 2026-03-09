# Noctua

**Real-time autonomous cybersecurity agent built in pure Go.**

Monitors processes, network connections, and filesystem changes. Detects threats through behavioral analysis, cross-correlation, machine learning anomaly detection (Isolation Forest with intelligent retraining), threat intelligence enrichment, and Sigma rule matching. Escalates severity through a finite state machine and can auto-block threats via firewall.

> **[Leia em Português](#documentação-em-português)** — Full Portuguese documentation below.

[![CI](https://github.com/KaioH3/noctua/actions/workflows/ci.yml/badge.svg)](https://github.com/KaioH3/noctua/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev)
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

---

## Por que Noctua?

A maioria das ferramentas de segurança de host ou é simples demais (checa uma lista de portas) ou exige infraestrutura pesada (SIEM, ELK, Wazuh). Noctua preenche esse espaço: um **binário único** que roda um pipeline completo de detecção no próprio host, sem dependências externas.

| O que faz | Como |
|---|---|
| Detecta processos novos/suspeitos | Escaneia `/proc` via gopsutil, compara com baseline aprendido |
| Identifica atividade de rede suspeita | Monitora conexões ESTABLISHED, portas C2, taxas de conexão |
| Vigia arquivos críticos | Hash SHA-256 de `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, etc. |
| Correlaciona entre fontes | Se o mesmo PID tem atividade suspeita em processo + rede + filesystem, o score multiplica |
| Detecta ameaças desconhecidas | Isolation Forest (ML não-supervisionado) identifica outliers estatísticos |
| Retreina automaticamente | Detecta drift no modelo e retreina quando o comportamento do sistema muda |
| Enriquece com threat intel | Reputação AbuseIPDB, localização GeoIP, hash MalwareBazaar, pulses OTX |
| Aplica regras Sigma | 20 regras YAML embarcadas, extensível com regras customizadas |
| Adapta-se ao longo do tempo | Feedback loop reduz peso de regras que geram falsos positivos |
| Bloqueia ameaças | Bloqueio automático via iptables/pfctl/netsh (opcional) |

---

## Início Rápido

```bash
# Clonar e compilar
git clone https://github.com/KaioH3/noctua.git
cd noctua
go build -o noctua ./cmd/noctua/

# Gerar configuração padrão
./noctua --gen-config

# Iniciar com dashboard web
sudo ./noctua --web
# Dashboard → http://localhost:9000
```

Isso é tudo. O Noctua vai:
1. Aprender o comportamento normal do sistema por 5 minutos
2. Começar a monitorar e detectar ameaças
3. Retreinar o modelo de anomalias automaticamente quando o sistema mudar

### Parar o Noctua

```bash
# De qualquer terminal:
./noctua --stop

# Ou Ctrl+C no terminal onde está rodando
```

---

## Referência do CLI

```
noctua [flags]
```

| Flag | Curta | Default | Descrição |
|---|---|---|---|
| `--web` | `-w` | `false` | Habilita dashboard web |
| `--port` | `-p` | `9000` | Porta do dashboard |
| `--config` | `-c` | `noctua.json` | Caminho do arquivo de configuração |
| `--gen-config` | | `false` | Gera config padrão e sai |
| `--stop` | | `false` | Para a instância rodando |

### Exemplos

```bash
noctua --gen-config              # gera noctua.json com valores padrão
noctua -w                        # inicia com dashboard em :9000
noctua -w -p 8080                # dashboard em porta customizada
noctua -c prod.json -w           # config customizado + dashboard
noctua --stop                    # para instância rodando
```

> Configurações avançadas (intervalo de scan, período de learning, firewall, notificações desktop, etc.) ficam no arquivo JSON. Gere um com `--gen-config` e edite conforme necessário.

---

## Configuração

Gere o arquivo padrão:

```bash
./noctua --gen-config
```

Isso cria `noctua.json` (veja o JSON completo na [seção em inglês](#configuration)).

### Referência de Campos

| Campo | Tipo | Descrição |
|---|---|---|
| `scan_interval_seconds` | int | Intervalo entre scans de processos/rede/filesystem |
| `learning_period_minutes` | int | Duração da fase de aprendizado (0 = pular) |
| `thresholds.*` | float | Limiares de score para cada estado do FSM |
| `watched_paths` | []string | Arquivos monitorados por alteração (SHA-256) |
| `suspicious_ports` | []int | Portas que indicam atividade C2 |
| `trusted_processes` | []string | Processos ignorados (`*` no final = prefixo) |
| `notify_desktop` | bool | Notificações desktop (notify-send/osascript) |
| `notify_webhook` | string | URL webhook para alertas (POST JSON) |
| `log_file` | string | Arquivo de log |
| `firewall_enabled` | bool | Auto-bloqueio via iptables/pfctl/netsh |
| `anomaly.num_trees` | int | Número de árvores do Isolation Forest |
| `anomaly.sample_size` | int | Tamanho da subamostra por árvore |
| `anomaly.max_buffer` | int | Tamanho do buffer circular para retreino |
| `anomaly.drift_threshold` | float | Desvios padrão para detectar drift (2.0 = 2σ) |
| `anomaly.drift_window_size` | int | Janela de scores recentes para comparação |
| `anomaly.fp_rate_threshold` | float | Taxa de FP que dispara retreino (0.3 = 30%) |
| `anomaly.check_interval_min` | int | Intervalo de checagem de drift (minutos) |

### Variáveis de Ambiente

| Variável | Descrição |
|---|---|
| `NOCTUA_ABUSEIPDB_KEY` | Chave API do [AbuseIPDB](https://www.abuseipdb.com/) |
| `NOCTUA_OTX_KEY` | Chave API do [AlienVault OTX](https://otx.alienvault.com/) |

Para GeoIP, baixe `GeoLite2-City.mmdb` do [MaxMind](https://www.maxmind.com/) e coloque em `~/.noctua/GeoLite2-City.mmdb`.

---

## Pipeline de Detecção

Cada evento passa por 7 estágios antes de chegar ao FSM:

```
  Monitores (processo / rede / filesystem)
      │
      ▼
  1. Heuristic Engine .............. Scoring baseado em regras (path suspeito,
      │                              mimicry de nome, portas C2, mods de arquivos...)
      ▼
  2. Cross-Correlator .............. Correlação multi-fonte por PID
      │                              6 detectores de padrão de ataque
      │                              Multiplicador: 1x / 1.5x / 2.5x
      ▼
  3. Anomaly Detector .............. Isolation Forest (100 árvores, 256 amostras)
      │                              Treinado no baseline, scores novos eventos
      │                              Retreino automático por drift detection
      ▼
  4. Threat Intel Enrichment ....... AbuseIPDB + GeoIP + MalwareBazaar + OTX
      │                              Cache em disco (TTL 24h)
      ▼
  5. Sigma Rule Engine ............. 20 regras embarcadas + YAML customizadas
      │                              Suporta contains, startswith, endswith,
      │                              wildcard, regex, AND/OR/NOT, 1-of
      ▼
  6. Classificação de Severidade ... INFO < LOW < MEDIUM < HIGH < CRITICAL
      │
      ▼
  7. FSM Automaton ................. Clean → Watching → Suspicious → Threat → Blocked
      │                              Decay de score ao longo do tempo (5/min)
      │                              Auto-remoção após 10min com score zero
      ▼
  Notifier (stdout + logfile + desktop + webhook)
  Dashboard (HTMX + SSE live stream)
  Firewall (iptables / pfctl / netsh)
```

---

## Padrões de Ataque Detectados

O cross-correlator identifica estes padrões multi-fonte:

| Padrão | Condições | Bonus |
|---|---|---|
| **Reverse Shell** | Processo de `/tmp/` ou `/dev/shm/` + conexão a porta C2 (4444, 5555, 1337...) | +40 |
| **Exfiltração de Dados** | Processo + rede (>20 conn) + filesystem (acesso a arquivo sensível) | +50 |
| **Persistência** | Processo + escrita em `/etc/crontab`, `/etc/ssh/sshd_config`, `/etc/sudoers` | +35 |
| **Movimento Lateral** | Processo + SSH (porta 22) para IP de rede privada | +45 |
| **Crypto Miner** | Processo com nome de alta entropia + atividade de rede | +40 |
| **Beaconing** | Conexões em intervalo regular (stddev < 15% da média) para mesmo IP | +55 |

---

## Detecção de Anomalias

Noctua usa um **Isolation Forest** implementado em Go puro (sem cgo, sem Python).

### Feature Vectors

Durante a fase de aprendizado, coleta vetores de 6 dimensões por evento:

```
[conexões/min, IPs_destino_únicos, portas_destino_únicas, intervalo_médio_conexão, criações_processo/min, modificações_arquivo/min]
```

### Scoring

Após treinamento (100 árvores, 256 amostras), eventos com score alto recebem bonus:

| Anomaly Score | Bonus |
|---|---|
| > 0.95 | +50 |
| > 0.85 | +30 |
| > 0.70 | +15 |

### Retreino Inteligente com Detecção de Drift

O modelo não fica estático. Duas métricas combinadas decidem quando retreinar:

**Score Distribution Drift** — Compara os scores recentes (janela deslizante de 200) com o baseline original. Se a média recente desviar mais que 2σ do baseline, indica que o modelo ficou desatualizado.

**FP Rate** — Usa feedback do usuário (via API) para computar a taxa de falsos positivos. Se FP rate > 30% (com mínimo de 10 eventos), dispara retreino.

O retreino é atômico: o modelo novo é treinado com dados do buffer circular (últimas 1000 amostras) sem bloquear o scoring, e substituído via `atomic.Pointer`. Goroutines fazendo `Score()` durante o `Retrain()` continuam sem lock.

```
[+] Learning complete. Baseline: 381 processes. Now monitoring.
[*] Drift detection: check every 5m | threshold: 2.0σ | FP rate limit: 30%
    ...
[*] Drift detected (score mean shifted 2.3σ) — retraining anomaly model...
[+] Anomaly model retrained with 847 samples
```

---

## Regras Sigma

20 regras embarcadas no binário (sem arquivos externos):

| Categoria | Regras |
|---|---|
| **Processo** | Path suspeito, reverse shell, name mimicry, nome alta-entropia, crypto miner, ferramentas de enumeração, wget/curl de `/tmp`, chmod +x, compilador de `/tmp`, crontab/at |
| **Rede** | Portas C2, IRC, Tor, RDP/VNC outbound, SSH para rede interna |
| **Filesystem** | shadow, passwd, sudoers, crontab, sshd_config, hosts |

### Regras Customizadas

Adicione regras Sigma em `~/.noctua/sigma/` como YAML padrão:

```yaml
title: Minha Regra Customizada
level: high
logsource:
  category: process_creation
detection:
  selection:
    Image|contains: '/caminho/suspeito'
  condition: selection
```

**Modificadores suportados:** `contains`, `startswith`, `endswith`, `re` (regex), wildcard (`*`).

**Condições suportadas:** `and`, `or`, `not`, `1 of selection*`, `all of selection*`.

---

## Dashboard

Dashboard web em tempo real em **http://localhost:9000** (configurável com `-p`). Usa Server-Sent Events (SSE) para atualizações ao vivo.

Funcionalidades:
- Stream de eventos em tempo real com badges de severidade
- Tracking de entidades (estados do FSM, scores, última atividade)
- Indicadores de anomaly detection e threat intel
- Uptime, contagem de processos, ameaças ativas, nível de ameaça global
- Contagem de regras Sigma carregadas

Construído com HTMX + Pico CSS — leve, sem npm, sem bundler.

---

## API

Todos os endpoints retornam JSON.

| Método | Endpoint | Descrição |
|---|---|---|
| `GET` | `/api/status` | Versão, uptime, threat level, status dos componentes |
| `GET` | `/api/events` | Eventos recentes (últimos 500) |
| `GET` | `/api/entities` | Todas as entidades rastreadas com estado do FSM |
| `GET` | `/api/correlations?pid=N` | Grafo de correlação (nós + arestas) para um PID |
| `GET` | `/api/intel?ip=X.X.X.X` | Lookup de threat intel (AbuseIPDB + GeoIP + OTX) |
| `GET` | `/api/feedback` | Estatísticas de feedback por regra |
| `POST` | `/api/feedback` | Enviar falso positivo (ver exemplo abaixo) |
| `GET` | `/events/stream` | Stream SSE de eventos ao vivo |

### Exemplos

```bash
# Reportar falso positivo
curl -X POST http://localhost:9000/api/feedback \
  -H 'Content-Type: application/json' \
  -d '{"entity_id":"proc:12345:curl","rule_name":"suspicious_path","false_positive":true}'

# Status do sistema
curl -s http://localhost:9000/api/status | python3 -m json.tool

# Stream de eventos ao vivo
curl -N http://localhost:9000/events/stream
```

---

## Processos Confiáveis

Noctua ignora processos na lista `trusted_processes`. Suporta wildcard com `*` no final para prefix match:

```json
{
  "trusted_processes": [
    "systemd",         "match exato"
    "kworker*",        "prefixo: kworker/3:2-events, kworker/u48:0-iou_exit, etc."
    "meu-daemon*"      "prefixo: qualquer processo começando com meu-daemon"
  ]
}
```

`kworker*` vem incluído por padrão para filtrar kernel worker threads que geram ruído.

---

## Máquina de Estados (FSM)

Cada entidade (processo, conexão de rede, IP) é rastreada por uma FSM de 5 estados:

```
Clean ──→ Watching ──→ Suspicious ──→ Threat ──→ Blocked
  ↑          │             │            │
  └──────────┴─────────────┴────────────┘
              (decay de score ao longo do tempo)
```

| Estado | Score Mínimo | Significado |
|---|---|---|
| **Clean** | 0 | Comportamento normal |
| **Watching** | 15 | Atividade levemente anômala, monitorando |
| **Suspicious** | 35 | Padrão preocupante, investigar |
| **Threat** | 65 | Ameaça confirmada |
| **Blocked** | 90 | Ameaça bloqueada (se firewall habilitado) |

O score decai 5 pontos por minuto. Entidades voltam para Clean quando o score zera.

---

## Build e Testes

```bash
# Pré-requisito: Go 1.22+

# Compilar
go build -o noctua ./cmd/noctua/

# Rodar todos os testes (93 testes)
go test ./...

# Testes com output detalhado
go test -v ./internal/anomaly/

# Cross-compile
GOOS=windows go build -o noctua.exe ./cmd/noctua/
GOOS=darwin  go build -o noctua-mac ./cmd/noctua/
```

### Cobertura de Testes por Pacote

| Pacote | Testes | Cobertura |
|---|---|---|
| `anomaly` | 21 | Isolation Forest, feature extraction, drift detection, retrain atômico, E2E |
| `correlator` | 27 | Grafo de correlação, 6 padrões de ataque, beaconing, feedback |
| `sigma` | 20 | Loader YAML, matcher de condições, modificadores, regras embarcadas |
| `automaton` | 12 | Transições FSM, decay, entity tracking |
| `heuristic` | 9 | Scoring por regras, classificação de severidade |
| `event` | 4 | Bus pub/sub, subscribe/publish |

---

## Estrutura do Projeto

```
noctua/
├── cmd/noctua/                CLI entry point (pflag, PID file, --stop)
├── internal/
│   ├── agent/                 Orquestrador principal (wiring do pipeline, drift check loop)
│   ├── anomaly/               Isolation Forest + feature extraction + drift monitor
│   │   ├── detector.go        Detector com buffer circular, atomic pointer, retrain
│   │   ├── drift.go           DriftMonitor (janela deslizante, detecção de shift)
│   │   ├── features.go        Extrator de feature vectors (6 dimensões)
│   │   ├── iforest.go         Isolation Forest puro (fit, score, subsample)
│   │   ├── drift_test.go      Testes de drift detection
│   │   ├── detector_test.go   Testes do detector (retrain, atomic swap)
│   │   └── e2e_test.go        Teste end-to-end: train → drift → retrain
│   ├── automaton/             Máquina de estados finita (5 estados)
│   ├── config/                Configuração JSON com defaults sensatos
│   ├── correlator/            Grafo de correlação + 6 padrões de ataque + beaconing + feedback
│   ├── event/                 Struct Event + barramento pub/sub
│   ├── firewall/              iptables (Linux), pfctl (macOS), netsh (Windows)
│   ├── heuristic/             Engine de scoring baseado em regras
│   ├── intel/                 AbuseIPDB, GeoIP, MalwareBazaar, OTX
│   ├── monitor/               Monitores de processo, rede e filesystem
│   ├── notifier/              Desktop (notify-send), webhook, log em arquivo
│   ├── sigma/                 Loader + matcher de regras Sigma + 20 regras embarcadas
│   └── web/                   Dashboard (HTMX + SSE + Pico CSS)
├── noctua.json                Configuração (gerada com --gen-config)
├── go.mod
└── go.sum
```

**44 arquivos Go | ~6700 linhas | 93 testes**

---

## License / Licença

MIT
