//go:build windows

package action

import (
	"fmt"
	"os"
	"os/exec"
)

func sigterm() os.Signal { return os.Interrupt }
func sigkill() os.Signal { return os.Kill }

func (a *Actor) renice(pid int32) error {
	// IDLE_PRIORITY_CLASS = 64 on Windows
	cmd := exec.Command("wmic", "process", "where",
		fmt.Sprintf("processid=%d", pid), "CALL", "SetPriority", "64")
	return cmd.Run()
}

func processAlive(pid int32) bool {
	p, err := os.FindProcess(int(pid))
	if err != nil {
		return false
	}
	// On Windows, FindProcess always succeeds; check via tasklist.
	cmd := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/NH")
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	_ = p
	return len(out) > 0 && string(out) != "INFO: No tasks are running which match the specified criteria.\r\n"
}
