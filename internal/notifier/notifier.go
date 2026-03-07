package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"noctua/internal/config"
	"noctua/internal/event"
)

type Notifier struct {
	cfg     *config.Config
	logFile *os.File
}

func New(cfg *config.Config) (*Notifier, error) {
	var logFile *os.File
	if cfg.LogFile != "" {
		f, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("opening log file: %w", err)
		}
		logFile = f
	}
	return &Notifier{cfg: cfg, logFile: logFile}, nil
}

func (n *Notifier) Close() {
	if n.logFile != nil {
		n.logFile.Close()
	}
}

func (n *Notifier) Notify(e event.Event) {
	// always print to stdout
	fmt.Println(e.Format())

	// log to file
	if n.logFile != nil {
		line := fmt.Sprintf("[%s] [%s] [%s] %s | entity=%s score=%.1f\n",
			e.Timestamp.Format(time.RFC3339),
			e.Severity.String(),
			e.Source,
			e.Message,
			e.EntityID,
			e.Score,
		)
		n.logFile.WriteString(line)
	}

	// desktop notification for high+ severity
	if n.cfg.NotifyDesktop && e.Severity >= event.High {
		n.desktopNotify(e)
	}

	// webhook for medium+ severity
	if n.cfg.NotifyWebhook != "" && e.Severity >= event.Medium {
		go n.webhookNotify(e)
	}
}

func (n *Notifier) NotifyTransition(entityID string, from, to string, score float64) {
	msg := fmt.Sprintf("State change: %s [%s → %s] (score: %.1f)", entityID, from, to, score)
	fmt.Printf("\033[35m[%s] [STATE]    %s\033[0m\n",
		time.Now().Format("2006-01-02 15:04:05"), msg)

	if n.logFile != nil {
		line := fmt.Sprintf("[%s] [STATE] %s\n", time.Now().Format(time.RFC3339), msg)
		n.logFile.WriteString(line)
	}
}

func (n *Notifier) desktopNotify(e event.Event) {
	title := fmt.Sprintf("Noctua [%s]", e.Severity.String())
	body := e.Message

	switch runtime.GOOS {
	case "linux":
		urgency := "normal"
		if e.Severity >= event.Critical {
			urgency = "critical"
		}
		exec.Command("notify-send", "-u", urgency, "-a", "Noctua", title, body).Run()
	case "darwin":
		script := fmt.Sprintf(`display notification "%s" with title "%s"`, body, title)
		exec.Command("osascript", "-e", script).Run()
	}
}

func (n *Notifier) webhookNotify(e event.Event) {
	payload := map[string]any{
		"timestamp": e.Timestamp.Format(time.RFC3339),
		"severity":  e.Severity.String(),
		"source":    e.Source,
		"kind":      e.Kind,
		"entity_id": e.EntityID,
		"message":   e.Message,
		"score":     e.Score,
		"details":   e.Details,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}

	client := &http.Client{Timeout: 5 * time.Second}
	client.Post(n.cfg.NotifyWebhook, "application/json", bytes.NewReader(data))
}
