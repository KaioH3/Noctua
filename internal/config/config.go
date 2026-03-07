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
	Enabled    bool `json:"enabled"`
	NumTrees   int  `json:"num_trees"`
	SampleSize int  `json:"sample_size"`
}

type ThreatIntelConfig struct {
	AbuseIPDBKey    string `json:"abuseipdb_key,omitempty"`
	GeoIPPath       string `json:"geoip_path,omitempty"`
	OTXKey          string `json:"otx_key,omitempty"`
	CacheTTLMinutes int    `json:"cache_ttl_minutes"`
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

	Correlator    CorrelatorConfig  `json:"correlator"`
	Anomaly       AnomalyConfig     `json:"anomaly"`
	ThreatIntel   ThreatIntelConfig `json:"threat_intel"`
	SigmaRulesDir string            `json:"sigma_rules_dir,omitempty"`
}

func Default() *Config {
	homeDir, _ := os.UserHomeDir()

	c := &Config{
		ScanIntervalSec:   10,
		LearningPeriodMin: 3,
		Thresholds: Thresholds{
			Watching:    15,
			Suspicious:  35,
			Threat:      65,
			Blocked:     90,
			DecayPerMin: 5,
		},
		SuspiciousPorts: []uint32{
			4444, 5555, 6666, 8888, 9999, // common C2
			6667, 6697,                     // IRC
			1337,                           // leet
			3389,                           // RDP (outbound is suspicious)
			5900,                           // VNC (outbound is suspicious)
		},
		TrustedProcesses: []string{
			"systemd", "init", "kthreadd", "sshd", "cron",
			"NetworkManager", "pulseaudio", "pipewire",
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
			Enabled:    true,
			NumTrees:   100,
			SampleSize: 256,
		},
		ThreatIntel: ThreatIntelConfig{
			AbuseIPDBKey:    os.Getenv("NOCTUA_ABUSEIPDB_KEY"),
			GeoIPPath:       filepath.Join(homeDir, ".noctua", "GeoLite2-City.mmdb"),
			OTXKey:          os.Getenv("NOCTUA_OTX_KEY"),
			CacheTTLMinutes: 1440,
		},
		SigmaRulesDir: filepath.Join(homeDir, ".noctua", "sigma"),
	}

	switch runtime.GOOS {
	case "linux", "darwin":
		c.WatchedPaths = []string{
			"/etc/passwd",
			"/etc/shadow",
			"/etc/crontab",
			"/etc/ssh/sshd_config",
			"/etc/sudoers",
			"/etc/hosts",
		}
	case "windows":
		c.WatchedPaths = []string{
			`C:\Windows\System32\drivers\etc\hosts`,
			`C:\Windows\System32\config\SAM`,
			`C:\Windows\System32\config\SYSTEM`,
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
