package action

import (
	"fmt"
	"os"
	"sync"
	"time"

	"noctua/internal/config"
	"noctua/internal/monitor"
)

// Actor executes process actions (notify / renice / kill) when the resource
// guard detects a runaway process. All operations are safe to call concurrently.
type Actor struct {
	cfg     *config.ResourceGuardConfig
	killing sync.Map // int32 pid → struct{}: prevents duplicate kill goroutines
}

func New(cfg *config.ResourceGuardConfig) *Actor {
	return &Actor{cfg: cfg}
}

// Handle executes the configured action for the given process.
// It is a no-op when Action == "notify" (the event pipeline already notified).
func (a *Actor) Handle(pid int32, name, reason string) {
	if !a.cfg.Enabled {
		return
	}
	if monitor.IsExemptProcess(name, a.cfg.ExemptProcesses) {
		return
	}

	switch a.cfg.Action {
	case "renice":
		if err := a.renice(pid); err == nil {
			fmt.Printf("\033[33m[!] RENICE: %s (PID %d) → nice %d [%s]\033[0m\n",
				name, pid, a.cfg.ReniceValue, reason)
		}
	case "kill":
		// Use sync.Map to guarantee at most one kill goroutine per PID.
		if _, loaded := a.killing.LoadOrStore(pid, struct{}{}); !loaded {
			go a.killGraceful(pid, name, reason)
		}
	}
}

func (a *Actor) killGraceful(pid int32, name, reason string) {
	defer a.killing.Delete(pid)

	p, err := os.FindProcess(int(pid))
	if err != nil {
		return
	}

	fmt.Printf("\033[1;31m[!] KILL (SIGTERM): %s (PID %d) — %s\033[0m\n", name, pid, reason)
	if err := p.Signal(sigterm()); err != nil {
		return
	}

	// Wait up to 5 seconds for graceful exit.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		if !processAlive(pid) {
			fmt.Printf("\033[32m[+] %s (PID %d) exited after SIGTERM\033[0m\n", name, pid)
			return
		}
	}

	fmt.Printf("\033[1;31m[!] KILL (SIGKILL): %s (PID %d) did not exit — forcing\033[0m\n", name, pid)
	_ = p.Signal(sigkill())
}
