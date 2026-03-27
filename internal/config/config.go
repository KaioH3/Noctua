package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

type Thresholds struct {
	Watching      float64 `json:"watching"`
	Suspicious    float64 `json:"suspicious"`
	Threat        float64 `json:"threat"`
	Blocked       float64 `json:"blocked"`
	DecayPerMin   float64 `json:"decay_per_minute"`
}

type CorrelatorConfig struct {
	Enabled         bool    `json:"enabled"`
	TimeWindowSec   int     `json:"time_window_sec"`
	TwoSourceMult   float64 `json:"two_source_mult"`
	ThreeSourceMult float64 `json:"three_source_mult"`
}

type AnomalyConfig struct {
	Enabled         bool    `json:"enabled"`
	NumTrees        int     `json:"num_trees"`
	SampleSize      int     `json:"sample_size"`
	MaxBuffer       int     `json:"max_buffer"`
	DriftThreshold  float64 `json:"drift_threshold"`
	DriftWindowSize int     `json:"drift_window_size"`
	FPRateThreshold float64 `json:"fp_rate_threshold"`
	CheckIntervalMin int    `json:"check_interval_min"`
}

type ThreatIntelConfig struct {
	AbuseIPDBKey    string `json:"abuseipdb_key,omitempty"`
	GeoIPPath       string `json:"geoip_path,omitempty"`
	OTXKey          string `json:"otx_key,omitempty"`
	CacheTTLMinutes int    `json:"cache_ttl_minutes"`
}

type ResourceGuardConfig struct {
	Enabled           bool     `json:"enabled"`
	CPUThreshold      float64  `json:"cpu_threshold"`
	MemoryThresholdMB uint64   `json:"memory_threshold_mb"`
	SustainedSeconds  int      `json:"sustained_seconds"`
	Action            string   `json:"action"` // "notify" | "renice" | "kill"
	ReniceValue       int      `json:"renice_value"`
	ExemptProcesses   []string `json:"exempt_processes"`
	SpawnLoopWindow   int      `json:"spawn_loop_window_sec"`
	SpawnLoopLimit    int      `json:"spawn_loop_limit"`
}

type Config struct {
	ScanIntervalSec    int        `json:"scan_interval_seconds"`
	LearningPeriodMin  int        `json:"learning_period_minutes"`
	Thresholds         Thresholds `json:"thresholds"`
	WatchedPaths       []string   `json:"watched_paths"`
	SuspiciousPorts    []uint32   `json:"suspicious_ports"`
	TrustedProcesses   []string   `json:"trusted_processes"`
	NotifyDesktop      bool       `json:"notify_desktop"`
	NotifyWebhook      string     `json:"notify_webhook,omitempty"`
	LogFile            string     `json:"log_file"`
	FirewallEnabled    bool       `json:"firewall_enabled"`

	Correlator    CorrelatorConfig    `json:"correlator"`
	Anomaly       AnomalyConfig       `json:"anomaly"`
	ThreatIntel   ThreatIntelConfig   `json:"threat_intel"`
	ResourceGuard ResourceGuardConfig `json:"resource_guard"`
	SigmaRulesDir string              `json:"sigma_rules_dir,omitempty"`
}

func Default() *Config {
	homeDir, _ := os.UserHomeDir()

	c := &Config{
		ScanIntervalSec:   10,
		LearningPeriodMin: 5,
		Thresholds: Thresholds{
			Watching:    15,
			Suspicious:  35,
			Threat:      65,
			Blocked:     90,
			DecayPerMin: 5,
		},
		SuspiciousPorts: []uint32{
			// C2 / backdoor classics
			4444, 5555, 6666, 8888, 9999,
			1337, 31337,
			// IRC (often used by botnets)
			6667, 6697,
			// remote desktop outbound (suspicious from workstation)
			3389, // RDP
			5900, 5901, 5902, // VNC
			// SSH outbound (data exfil / tunneling)
			22,
			// Metasploit / Cobalt Strike defaults
			4443, 8443, 50050,
			// common RAT / trojan ports
			1234, 12345, 54321,
			3460,  // backdoor
			7777,  // backdoor
			9090,  // common webshell
			// crypto mining pools
			3333, 14444, 45700,
			// SOCKS proxy (potential tunneling)
			1080, 9050, 9150,
		},
		TrustedProcesses: []string{
			// system core
			"systemd", "init", "kthreadd", "sshd", "cron", "crond",
			"kworker*", "ksoftirqd*", "migration*", "rcu_*",
			// networking
			"NetworkManager", "wpa_supplicant", "dhclient", "dhcpcd",
			"systemd-resolved", "systemd-networkd", "avahi-daemon",
			// audio / display
			"pulseaudio", "pipewire", "pipewire-pulse", "wireplumber",
			"Xorg", "Xwayland", "gnome-shell", "kwin*", "plasmashell",
			"gdm*", "sddm", "lightdm",
			// D-Bus / polkit
			"dbus-daemon", "dbus-broker", "polkitd",
			// package managers (brief spikes)
			"apt", "dpkg", "pacman", "dnf", "yum", "zypper", "flatpak",
			// journaling / logging
			"systemd-journald", "rsyslogd", "auditd",
			// misc system
			"udisksd", "upower", "thermald", "irqbalance",
			"accounts-daemon", "colord", "fwupd",
			// dev tools (suppress new-process noise; resource guard still watches them)
			"code", "code-oss", "node", "npm", "npx",
			"python3", "python", "go", "cargo", "rustc", "java", "gradle",
			"chrome", "chromium", "firefox", "brave-browser", "agent-browser",
		},
		NotifyDesktop:   true,
		LogFile:         "noctua.log",
		FirewallEnabled: false, // off by default — safety first
		Correlator: CorrelatorConfig{
			Enabled:         true,
			TimeWindowSec:   60,
			TwoSourceMult:   1.5,
			ThreeSourceMult: 2.5,
		},
		Anomaly: AnomalyConfig{
			Enabled:          true,
			NumTrees:         100,
			SampleSize:       256,
			MaxBuffer:        1000,
			DriftThreshold:   2.0,
			DriftWindowSize:  200,
			FPRateThreshold:  0.3,
			CheckIntervalMin: 5,
		},
		ThreatIntel: ThreatIntelConfig{
			AbuseIPDBKey:    os.Getenv("NOCTUA_ABUSEIPDB_KEY"),
			GeoIPPath:       filepath.Join(homeDir, ".noctua", "GeoLite2-City.mmdb"),
			OTXKey:          os.Getenv("NOCTUA_OTX_KEY"),
			CacheTTLMinutes: 1440,
		},
		ResourceGuard: ResourceGuardConfig{
			Enabled:           true,
			CPUThreshold:      85.0,
			MemoryThresholdMB: 4096,
			SustainedSeconds:  30,
			Action:            "notify",
			ReniceValue:       19,
			ExemptProcesses:   []string{"systemd", "init", "kthreadd", "sshd", "kwin*", "plasmashell", "gnome-shell"},
			SpawnLoopWindow:   60,
			SpawnLoopLimit:    10,
		},
		SigmaRulesDir: filepath.Join(homeDir, ".noctua", "sigma"),
	}

	switch runtime.GOOS {
	case "linux", "darwin":
		c.WatchedPaths = []string{
			// authentication & authorization
			"/etc/passwd",
			"/etc/shadow",
			"/etc/sudoers",
			"/etc/group",
			"/etc/gshadow",
			// SSH
			"/etc/ssh/sshd_config",
			"/etc/ssh/ssh_config",
			// scheduled tasks
			"/etc/crontab",
			"/etc/cron.d",
			"/etc/anacrontab",
			// network & DNS
			"/etc/hosts",
			"/etc/resolv.conf",
			"/etc/nsswitch.conf",
			// system startup & services
			"/etc/rc.local",
			"/etc/environment",
			"/etc/profile",
			"/etc/ld.so.preload",
			// PAM (authentication modules)
			"/etc/pam.d",
			// firewall
			"/etc/iptables",
			"/etc/nftables.conf",
		}
	case "windows":
		c.WatchedPaths = []string{
			`C:\Windows\System32\drivers\etc\hosts`,
			`C:\Windows\System32\config\SAM`,
			`C:\Windows\System32\config\SYSTEM`,
			`C:\Windows\System32\config\SECURITY`,
			`C:\Windows\System32\config\SOFTWARE`,
			`C:\Windows\Tasks`,
			`C:\Windows\System32\Tasks`,
		}
	}

	return c
}

func Load(path string) (*Config, error) {
	c := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil // no config file = use defaults
		}
		return nil, err
	}

	if err := json.Unmarshal(data, c); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
