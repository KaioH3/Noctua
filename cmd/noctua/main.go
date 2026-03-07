package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"noctua/internal/agent"
	"noctua/internal/config"
	"noctua/internal/web"
)

func main() {
	configPath := flag.String("config", "noctua.json", "path to config file")
	genConfig := flag.Bool("gen-config", false, "generate default config and exit")
	scanInterval := flag.Int("interval", 0, "override scan interval (seconds)")
	learningMin := flag.Int("learning", -1, "override learning period (minutes, 0=skip)")
	noDesktop := flag.Bool("no-desktop", false, "disable desktop notifications")
	enableFW := flag.Bool("firewall", false, "enable automatic firewall blocking")
	webEnabled := flag.Bool("web", false, "enable web dashboard")
	webPort := flag.String("port", "9000", "web dashboard port")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Noctua — Cybersecurity Automaton Agent\n\n")
		fmt.Fprintf(os.Stderr, "Usage: noctua [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  noctua                        # run with defaults\n")
		fmt.Fprintf(os.Stderr, "  noctua -web                   # run with dashboard on :9000\n")
		fmt.Fprintf(os.Stderr, "  noctua -web -port 8080        # dashboard on :8080\n")
		fmt.Fprintf(os.Stderr, "  noctua -learning 0            # skip learning phase\n")
	}

	flag.Parse()

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

	if *scanInterval > 0 {
		cfg.ScanIntervalSec = *scanInterval
	}
	if *learningMin >= 0 {
		cfg.LearningPeriodMin = *learningMin
	}
	if *noDesktop {
		cfg.NotifyDesktop = false
	}
	if *enableFW {
		cfg.FirewallEnabled = true
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		fmt.Printf("\n\033[33m[*] Received %s, shutting down gracefully...\033[0m\n", sig)
		cancel()
	}()

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
	}

	if err := a.Run(ctx); err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "Agent error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\033[36m[*] Noctua stopped.\033[0m")
}
