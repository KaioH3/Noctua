package sigma

import (
	"testing"

	"noctua/internal/event"
)

func TestMatchExact(t *testing.T) {
	rule := Rule{
		Detection: map[string]any{
			"selection":  map[string]any{"ProcessName": "malware"},
			"condition":  "selection",
		},
	}
	e := &event.Event{
		Details: map[string]any{"name": "malware"},
	}
	if !Match(rule, e) {
		t.Error("expected exact match")
	}
}

func TestMatchNoMatch(t *testing.T) {
	rule := Rule{
		Detection: map[string]any{
			"selection":  map[string]any{"ProcessName": "malware"},
			"condition":  "selection",
		},
	}
	e := &event.Event{
		Details: map[string]any{"name": "firefox"},
	}
	if Match(rule, e) {
		t.Error("should not match")
	}
}

func TestMatchWildcard(t *testing.T) {
	rule := Rule{
		Detection: map[string]any{
			"selection":  map[string]any{"Image": "*/tmp/*"},
			"condition":  "selection",
		},
	}
	e := &event.Event{
		Details: map[string]any{"exe": "/tmp/evil"},
	}
	if !Match(rule, e) {
		t.Error("expected wildcard match")
	}
}

func TestMatchContains(t *testing.T) {
	rule := Rule{
		Detection: map[string]any{
			"selection":  map[string]any{"Image|contains": "/tmp/"},
			"condition":  "selection",
		},
	}
	e := &event.Event{
		Details: map[string]any{"exe": "/usr/tmp/evil"},
	}
	if !Match(rule, e) {
		t.Error("expected contains match")
	}
}

func TestMatchStartswith(t *testing.T) {
	rule := Rule{
		Detection: map[string]any{
			"selection":  map[string]any{"Image|startswith": "/tmp"},
			"condition":  "selection",
		},
	}
	e := &event.Event{
		Details: map[string]any{"exe": "/tmp/evil"},
	}
	if !Match(rule, e) {
		t.Error("expected startswith match")
	}
}

func TestMatchEndswith(t *testing.T) {
	rule := Rule{
		Detection: map[string]any{
			"selection":  map[string]any{"Image|endswith": ".sh"},
			"condition":  "selection",
		},
	}
	e := &event.Event{
		Details: map[string]any{"exe": "/tmp/evil.sh"},
	}
	if !Match(rule, e) {
		t.Error("expected endswith match")
	}
}

func TestMatchRegex(t *testing.T) {
	rule := Rule{
		Detection: map[string]any{
			"selection":  map[string]any{"Image|re": "^/tmp/[a-z]+$"},
			"condition":  "selection",
		},
	}
	e := &event.Event{
		Details: map[string]any{"exe": "/tmp/evil"},
	}
	if !Match(rule, e) {
		t.Error("expected regex match")
	}
}

func TestConditionAnd(t *testing.T) {
	rule := Rule{
		Detection: map[string]any{
			"sel1":      map[string]any{"ProcessName": "curl"},
			"sel2":      map[string]any{"Image|contains": "/tmp/"},
			"condition": "sel1 and sel2",
		},
	}

	e := &event.Event{
		Details: map[string]any{"name": "curl", "exe": "/tmp/curl"},
	}
	if !Match(rule, e) {
		t.Error("expected AND match")
	}

	e2 := &event.Event{
		Details: map[string]any{"name": "curl", "exe": "/usr/bin/curl"},
	}
	if Match(rule, e2) {
		t.Error("AND should fail when one condition doesn't match")
	}
}

func TestConditionOr(t *testing.T) {
	rule := Rule{
		Detection: map[string]any{
			"sel1":      map[string]any{"ProcessName": "curl"},
			"sel2":      map[string]any{"ProcessName": "wget"},
			"condition": "sel1 or sel2",
		},
	}

	e := &event.Event{
		Details: map[string]any{"name": "wget"},
	}
	if !Match(rule, e) {
		t.Error("expected OR match")
	}
}

func TestConditionNot(t *testing.T) {
	rule := Rule{
		Detection: map[string]any{
			"selection":  map[string]any{"ProcessName": "malware"},
			"condition":  "not selection",
		},
	}

	e := &event.Event{
		Details: map[string]any{"name": "firefox"},
	}
	if !Match(rule, e) {
		t.Error("expected NOT match (not malware)")
	}

	e2 := &event.Event{
		Details: map[string]any{"name": "malware"},
	}
	if Match(rule, e2) {
		t.Error("NOT should negate match")
	}
}

func TestCondition1OfSelection(t *testing.T) {
	rule := Rule{
		Detection: map[string]any{
			"selection_1": map[string]any{"ProcessName": "curl"},
			"selection_2": map[string]any{"ProcessName": "wget"},
			"condition":   "1 of selection*",
		},
	}

	e := &event.Event{
		Details: map[string]any{"name": "wget"},
	}
	if !Match(rule, e) {
		t.Error("expected 1 of selection* match")
	}

	e2 := &event.Event{
		Details: map[string]any{"name": "firefox"},
	}
	if Match(rule, e2) {
		t.Error("1 of selection* should not match firefox")
	}
}

func TestFieldMapping(t *testing.T) {
	rule := Rule{
		Detection: map[string]any{
			"selection":  map[string]any{"Image": "/usr/bin/curl"},
			"condition":  "selection",
		},
	}
	e := &event.Event{
		Details: map[string]any{"exe": "/usr/bin/curl"},
	}
	if !Match(rule, e) {
		t.Error("Image should map to exe")
	}
}

func TestContainsListMatch(t *testing.T) {
	rule := Rule{
		Detection: map[string]any{
			"selection": map[string]any{
				"Image|contains": []any{"/tmp/", "/dev/shm/"},
			},
			"condition": "selection",
		},
	}
	e := &event.Event{
		Details: map[string]any{"exe": "/dev/shm/payload"},
	}
	if !Match(rule, e) {
		t.Error("expected contains list match")
	}
}

func TestNilDetection(t *testing.T) {
	rule := Rule{Detection: nil}
	e := &event.Event{Details: map[string]any{}}
	if Match(rule, e) {
		t.Error("nil detection should not match")
	}
}

func TestSourceMatchesFilter(t *testing.T) {
	engine := NewEngine([]Rule{
		{
			Title: "Process Rule",
			Level: "medium",
			Logsource: Logsource{Category: "process_creation"},
			Detection: map[string]any{
				"selection":  map[string]any{"ProcessName": "evil"},
				"condition":  "selection",
			},
		},
	})

	// Network event should not trigger process_creation rule
	e := &event.Event{
		Source:  "network",
		Details: map[string]any{"name": "evil"},
	}
	engine.Evaluate(e)
	if len(e.SigmaRules) > 0 {
		t.Error("process_creation rule should not match network event")
	}
}

func TestLevelToBonus(t *testing.T) {
	tests := []struct {
		level string
		want  float64
	}{
		{"critical", 60},
		{"high", 40},
		{"medium", 25},
		{"low", 10},
		{"informational", 5},
	}
	for _, tt := range tests {
		got := LevelToBonus(tt.level)
		if got != tt.want {
			t.Errorf("LevelToBonus(%q) = %f, want %f", tt.level, got, tt.want)
		}
	}
}
