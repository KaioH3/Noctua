package config

import (
	"encoding/json"
	"os"
	"runtime"
)

type Thresholds struct {
	Watching      float64 `json:"watching"`
	Suspicious    float64 `json:"suspicious"`
	Threat        float64 `json:"threat"`
	Blocked       float64 `json:"blocked"`
	DecayPerMin   float64 `json:"decay_per_minute"`
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
}

func Default() *Config {
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
	}

	if runtime.GOOS == "linux" {
		c.WatchedPaths = []string{
			"/etc/passwd",
			"/etc/shadow",
			"/etc/crontab",
			"/etc/ssh/sshd_config",
			"/etc/sudoers",
			"/etc/hosts",
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
