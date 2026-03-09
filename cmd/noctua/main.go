package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	flag "github.com/spf13/pflag"

	"noctua/internal/agent"
	"noctua/internal/config"
	"noctua/internal/web"
)

func pidFilePath() string {
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".noctua", "noctua.pid")
}

func writePIDFile() {
	path := pidFilePath()
	os.MkdirAll(filepath.Dir(path), 0755)
	os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0644)
}

func removePIDFile() {
	os.Remove(pidFilePath())
}

func stopRunning() {
	data, err := os.ReadFile(pidFilePath())
	if err != nil {
		fmt.Fprintln(os.Stderr, "Noctua is not running (no PID file)")
		os.Exit(1)
	}

	pid, err := strconv.Atoi(string(data))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Invalid PID file")
		os.Remove(pidFilePath())
		os.Exit(1)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Process %d not found\n", pid)
		os.Remove(pidFilePath())
		os.Exit(1)
	}

	if err := proc.Signal(syscall.SIGTERM); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to stop Noctua (PID %d): %v\n", pid, err)
		os.Remove(pidFilePath())
		os.Exit(1)
	}

	fmt.Printf("Noctua (PID %d) stopped.\n", pid)
	os.Remove(pidFilePath())
}

func main() {
	configPath := flag.StringP("config", "c", "noctua.json", "path to config file")
	genConfig := flag.Bool("gen-config", false, "generate default config and exit")
	webEnabled := flag.BoolP("web", "w", false, "enable web dashboard")
	webPort := flag.StringP("port", "p", "9000", "web dashboard port")
	stop := flag.Bool("stop", false, "stop a running Noctua instance")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Noctua — Cybersecurity Automaton Agent\n\n")
		fmt.Fprintf(os.Stderr, "Usage: noctua [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  noctua --gen-config            # generate default config\n")
		fmt.Fprintf(os.Stderr, "  noctua -w                      # dashboard on :9000\n")
		fmt.Fprintf(os.Stderr, "  noctua -w -p 8080              # dashboard on :8080\n")
		fmt.Fprintf(os.Stderr, "  noctua -c prod.json -w         # custom config + dashboard\n")
		fmt.Fprintf(os.Stderr, "  noctua --stop                  # stop running instance\n")
	}

	flag.Parse()

	if *stop {
		stopRunning()
		return
	}

	if *genConfig {
		cfg := config.Default()
		if err := cfg.Save(*configPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Default config written to %s\n", *configPath)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	writePIDFile()
	defer removePIDFile()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		fmt.Printf("\n\033[33m[*] Received %s, shutting down gracefully...\033[0m\n", sig)
		cancel()
	}()

	fmt.Println("\033[36m")
	fmt.Println("  ╔══════════════════════════════════════════╗")
	fmt.Println("  ║     Noctua — Cybersecurity Automaton     ║")
	fmt.Println("  ╚══════════════════════════════════════════╝")
	fmt.Println("\033[0m")

	a, err := agent.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating agent: %v\n", err)
		os.Exit(1)
	}

	if *webEnabled {
		addr := ":" + *webPort
		srv, err := web.NewServer(addr, a)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating web server: %v\n", err)
			os.Exit(1)
		}
		go func() {
			if err := srv.Start(); err != nil && err != http.ErrServerClosed {
				fmt.Fprintf(os.Stderr, "Web server error: %v\n", err)
			}
		}()
		fmt.Printf("\033[32m  ▸ Dashboard:  http://localhost:%s\033[0m\n", *webPort)
	} else {
		fmt.Println("\033[33m  ▸ Dashboard disabled (use --web to enable)\033[0m")
	}
	fmt.Printf("  ▸ Scan interval: %ds | Learning: %dm | Firewall: %v\n\n",
		cfg.ScanIntervalSec, cfg.LearningPeriodMin, cfg.FirewallEnabled)

	if err := a.Run(ctx); err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "Agent error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\033[36m[*] Noctua stopped.\033[0m")
}
