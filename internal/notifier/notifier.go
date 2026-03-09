package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
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
		line := fmt.Sprintf("[%s] [%s] [%s] %s | entity=%s score=%.1f",
			e.Timestamp.Format(time.RFC3339),
			e.Severity.String(),
			e.Source,
			e.Message,
			e.EntityID,
			e.Score,
		)
		if len(e.Patterns) > 0 {
			line += fmt.Sprintf(" patterns=%v", e.Patterns)
		}
		if len(e.SigmaRules) > 0 {
			line += fmt.Sprintf(" sigma=%v", e.SigmaRules)
		}
		if e.AnomalyScore > 0 {
			line += fmt.Sprintf(" anomaly=%.2f", e.AnomalyScore)
		}
		if e.Multiplier > 1 {
			line += fmt.Sprintf(" mult=%.1fx", e.Multiplier)
		}
		line += "\n"
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
	if len(e.Patterns) > 0 {
		body += fmt.Sprintf(" | Patterns: %s", strings.Join(e.Patterns, ", "))
	}
	if len(e.SigmaRules) > 0 {
		body += fmt.Sprintf(" | Sigma: %s", strings.Join(e.SigmaRules, ", "))
	}
	if geo := extractCountryFromIntel(e.ThreatIntel); geo != "" {
		body += fmt.Sprintf(" | Country: %s", geo)
	}

	switch runtime.GOOS {
	case "linux":
		urgency := "normal"
		if e.Severity >= event.Critical {
			urgency = "critical"
		}
		exec.Command("notify-send", "-u", urgency, "-a", "Noctua", title, body).Run()
	case "darwin":
		sanitize := func(s string) string {
			return strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`)
		}
		script := fmt.Sprintf(`display notification "%s" with title "%s"`, sanitize(body), sanitize(title))
		exec.Command("osascript", "-e", script).Run()
	case "windows":
		psTitle := strings.ReplaceAll(title, "'", "''")
		psBody := strings.ReplaceAll(body, "'", "''")
		script := fmt.Sprintf(`
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType=WindowsRuntime] | Out-Null
$xml = @'
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>%s</text>
      <text>%s</text>
    </binding>
  </visual>
</toast>
'@
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Noctua').Show(
    [Windows.UI.Notifications.ToastNotification]::new($doc)
)`, psTitle, psBody)
		exec.Command("powershell", "-NoProfile", "-Command", script).Run()
	}
}

func (n *Notifier) webhookNotify(e event.Event) {
	payload := map[string]any{
		"timestamp":     e.Timestamp.Format(time.RFC3339),
		"severity":      e.Severity.String(),
		"source":        e.Source,
		"kind":          e.Kind,
		"entity_id":     e.EntityID,
		"message":       e.Message,
		"score":         e.Score,
		"details":       e.Details,
		"patterns":      e.Patterns,
		"sigma_rules":   e.SigmaRules,
		"anomaly_score": e.AnomalyScore,
		"multiplier":    e.Multiplier,
		"threat_intel":  e.ThreatIntel,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}

	client := &http.Client{Timeout: 5 * time.Second}
	client.Post(n.cfg.NotifyWebhook, "application/json", bytes.NewReader(data))
}

func extractCountryFromIntel(ti map[string]any) string {
	if ti == nil {
		return ""
	}
	if geo, ok := ti["geoip"].(map[string]any); ok {
		if cc, ok := geo["country_code"].(string); ok {
			return cc
		}
	}
	return ""
}
