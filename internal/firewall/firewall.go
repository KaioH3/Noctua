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
	case "darwin":
		return &darwinFW{}
	case "windows":
		return &windowsFW{}
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

// --- macOS (pfctl) ---

type darwinFW struct{}

func (f *darwinFW) Available() bool {
	_, err := exec.LookPath("pfctl")
	return err == nil
}

func (f *darwinFW) BlockIP(ip string) error {
	if !f.Available() {
		return fmt.Errorf("pfctl not found")
	}
	cmd := exec.Command("sh", "-c",
		fmt.Sprintf(`echo "block drop from %s to any" | pfctl -ef -`, ip))
	return cmd.Run()
}

func (f *darwinFW) UnblockIP(ip string) error {
	return fmt.Errorf("pfctl unblock not implemented — flush rules manually")
}

// --- Windows (netsh) ---

type windowsFW struct{}

func (f *windowsFW) Available() bool {
	_, err := exec.LookPath("netsh")
	return err == nil
}

func (f *windowsFW) BlockIP(ip string) error {
	if !f.Available() {
		return fmt.Errorf("netsh not found")
	}
	ruleName := fmt.Sprintf("NoctuaBlock_%s", ip)
	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+ruleName,
		"dir=in", "action=block",
		"remoteip="+ip)
	return cmd.Run()
}

func (f *windowsFW) UnblockIP(ip string) error {
	if !f.Available() {
		return fmt.Errorf("netsh not found")
	}
	ruleName := fmt.Sprintf("NoctuaBlock_%s", ip)
	cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
		"name="+ruleName)
	return cmd.Run()
}

// --- Noop (unsupported platforms) ---

type noopFW struct{}

func (f *noopFW) Available() bool        { return false }
func (f *noopFW) BlockIP(ip string) error   { return fmt.Errorf("firewall not supported on %s", runtime.GOOS) }
func (f *noopFW) UnblockIP(ip string) error { return fmt.Errorf("firewall not supported on %s", runtime.GOOS) }
