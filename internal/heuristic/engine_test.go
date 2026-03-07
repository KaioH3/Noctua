package heuristic

import (
	"testing"
	"time"

	"noctua/internal/event"
)

func TestSuspiciousPath(t *testing.T) {
	eng := New()
	e := &event.Event{
		Source:    "process",
		Timestamp: time.Now(),
		Details:   map[string]any{"exe": "/tmp/backdoor", "name": "backdoor"},
	}
	score := eng.Score(e)
	if score < 30 {
		t.Errorf("suspicious path should score >= 30, got %f", score)
	}
}

func TestNameMimicry(t *testing.T) {
	eng := New()
	e := &event.Event{
		Source:    "process",
		Timestamp: time.Now(),
		Details:   map[string]any{"name": "sshd", "exe": "/tmp/sshd"},
	}
	score := eng.Score(e)
	// Should trigger both suspicious_path (30) and name_mimicry (50) = 80
	if score < 50 {
		t.Errorf("name mimicry should score >= 50, got %f", score)
	}
}

func TestNormalProcessLowScore(t *testing.T) {
	eng := New()
	e := &event.Event{
		Source:    "process",
		Timestamp: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		Details:   map[string]any{"name": "firefox", "exe": "/usr/bin/firefox"},
	}
	score := eng.Score(e)
	if score != 0 {
		t.Errorf("normal process should score 0, got %f", score)
	}
}

func TestUnusualHour(t *testing.T) {
	eng := New()
	e := &event.Event{
		Source:    "process",
		Timestamp: time.Date(2024, 1, 1, 3, 0, 0, 0, time.UTC), // 3 AM
		Details:   map[string]any{"name": "backup", "exe": "/tmp/backup"},
	}
	score := eng.Score(e)
	// suspicious_path (30) + unusual_hour (10) = 40
	if score < 40 {
		t.Errorf("unusual hour + suspicious path should score >= 40, got %f", score)
	}
}

func TestSuspiciousPort(t *testing.T) {
	eng := New()
	e := &event.Event{
		Source:    "network",
		Kind:      "suspicious_port",
		Timestamp: time.Now(),
		Details:   map[string]any{"remote_port": uint32(4444)},
	}
	score := eng.Score(e)
	if score < 25 {
		t.Errorf("suspicious port should score >= 25, got %f", score)
	}
}

func TestHighConnectionRate(t *testing.T) {
	eng := New()
	e := &event.Event{
		Source:    "network",
		Kind:      "high_conn_rate",
		Timestamp: time.Now(),
		Details:   map[string]any{"count": 55},
	}
	score := eng.Score(e)
	if score < 40 {
		t.Errorf("high connection rate (>50) should score >= 40, got %f", score)
	}
}

func TestCriticalFileModified(t *testing.T) {
	eng := New()
	e := &event.Event{
		Source:    "filesystem",
		Kind:      "file_modified",
		Timestamp: time.Now(),
		Details:   map[string]any{"path": "/etc/shadow"},
	}
	score := eng.Score(e)
	if score < 60 {
		t.Errorf("critical file modified should score >= 60, got %f", score)
	}
}

func TestRapidModifications(t *testing.T) {
	eng := New()
	e := &event.Event{
		Source:    "filesystem",
		Kind:      "rapid_changes",
		Timestamp: time.Now(),
		Details:   map[string]any{"count": 15},
	}
	score := eng.Score(e)
	if score < 70 {
		t.Errorf("rapid modifications should score >= 70, got %f", score)
	}
}

func TestClassifySeverityThresholds(t *testing.T) {
	tests := []struct {
		score float64
		want  event.Severity
	}{
		{0, event.Info},
		{14, event.Info},
		{15, event.Low},
		{29, event.Low},
		{30, event.Medium},
		{49, event.Medium},
		{50, event.High},
		{69, event.High},
		{70, event.Critical},
		{100, event.Critical},
	}
	for _, tt := range tests {
		got := ClassifySeverity(tt.score)
		if got != tt.want {
			t.Errorf("ClassifySeverity(%f) = %v, want %v", tt.score, got, tt.want)
		}
	}
}
