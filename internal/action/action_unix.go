//go:build !windows

package action

import (
	"os"
	"syscall"
)

func sigterm() os.Signal { return syscall.SIGTERM }
func sigkill() os.Signal { return syscall.SIGKILL }

func (a *Actor) renice(pid int32) error {
	return syscall.Setpriority(syscall.PRIO_PROCESS, int(pid), a.cfg.ReniceValue)
}

func processAlive(pid int32) bool {
	p, err := os.FindProcess(int(pid))
	if err != nil {
		return false
	}
	// Signal 0 checks process existence without sending a real signal.
	return p.Signal(syscall.Signal(0)) == nil
}
