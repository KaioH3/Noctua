package firewall

import (
	"fmt"
	"os/exec"
	"runtime"
)

type Firewall interface {
	BlockIP(ip string) error
	UnblockIP(ip string) error
	Available() bool
}

func New() Firewall {
	switch runtime.GOOS {
	case "linux":
		return &linuxFW{}
	default:
		return &noopFW{}
	}
}

// --- Linux (iptables) ---

type linuxFW struct{}

func (f *linuxFW) Available() bool {
	_, err := exec.LookPath("iptables")
	return err == nil
}

func (f *linuxFW) BlockIP(ip string) error {
	if !f.Available() {
		return fmt.Errorf("iptables not found")
	}
	cmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	return cmd.Run()
}

func (f *linuxFW) UnblockIP(ip string) error {
	if !f.Available() {
		return fmt.Errorf("iptables not found")
	}
	cmd := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
	return cmd.Run()
}

// --- Noop (unsupported platforms) ---

type noopFW struct{}

func (f *noopFW) Available() bool        { return false }
func (f *noopFW) BlockIP(ip string) error   { return fmt.Errorf("firewall not supported on %s", runtime.GOOS) }
func (f *noopFW) UnblockIP(ip string) error { return fmt.Errorf("firewall not supported on %s", runtime.GOOS) }
