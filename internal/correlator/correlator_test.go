package correlator

import (
	"testing"
	"time"

	"noctua/internal/event"
)

func TestMultiplierOneSources(t *testing.T) {
	c := New(60, 1.5, 2.5)
	e := &event.Event{
		EntityID:  "e1",
		Source:    "process",
		Timestamp: time.Now(),
		Score:     10,
		Details:   map[string]any{"pid": int32(100)},
	}
	result := c.Correlate(e)

	if result.Multiplier != 1.0 {
		t.Errorf("1 source: expected multiplier 1.0, got %f", result.Multiplier)
	}
}

func TestMultiplierTwoSources(t *testing.T) {
	c := New(60, 1.5, 2.5)
	now := time.Now()

	c.Correlate(&event.Event{
		EntityID:  "e1",
		Source:    "process",
		Timestamp: now,
		Score:     10,
		Details:   map[string]any{"pid": int32(100)},
	})

	e2 := &event.Event{
		EntityID:  "e2",
		Source:    "network",
		Timestamp: now.Add(1 * time.Second),
		Score:     10,
		Details:   map[string]any{"pid": int32(100)},
	}
	result := c.Correlate(e2)

	if result.Multiplier != 1.5 {
		t.Errorf("2 sources: expected multiplier 1.5, got %f", result.Multiplier)
	}
}

func TestMultiplierThreeSources(t *testing.T) {
	c := New(60, 1.5, 2.5)
	now := time.Now()

	c.Correlate(&event.Event{
		EntityID:  "e1",
		Source:    "process",
		Timestamp: now,
		Score:     10,
		Details:   map[string]any{"pid": int32(100)},
	})
	c.Correlate(&event.Event{
		EntityID:  "e2",
		Source:    "network",
		Timestamp: now.Add(1 * time.Second),
		Score:     10,
		Details:   map[string]any{"pid": int32(100)},
	})

	e3 := &event.Event{
		EntityID:  "e3",
		Source:    "filesystem",
		Timestamp: now.Add(2 * time.Second),
		Score:     10,
		Details:   map[string]any{"pid": int32(100)},
	}
	result := c.Correlate(e3)

	if result.Multiplier != 2.5 {
		t.Errorf("3 sources: expected multiplier 2.5, got %f", result.Multiplier)
	}
}

func TestPatternsAddedToEvent(t *testing.T) {
	c := New(60, 1.5, 2.5)
	now := time.Now()

	// Create a reverse shell scenario
	c.Correlate(&event.Event{
		EntityID:  "e1",
		Source:    "process",
		Timestamp: now,
		Score:     10,
		Details:   map[string]any{"pid": int32(100), "exe": "/tmp/backdoor"},
	})

	e2 := &event.Event{
		EntityID:  "e2",
		Source:    "network",
		Timestamp: now.Add(1 * time.Second),
		Score:     10,
		Details:   map[string]any{"pid": int32(100), "remote_port": uint32(4444)},
	}
	c.Correlate(e2)

	found := false
	for _, p := range e2.Patterns {
		if p == "reverse_shell" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected reverse_shell pattern in event, got %v", e2.Patterns)
	}
}

func TestZeroPIDNoCorrelation(t *testing.T) {
	c := New(60, 1.5, 2.5)
	e := &event.Event{
		EntityID:  "e1",
		Source:    "process",
		Timestamp: time.Now(),
		Score:     10,
		Details:   map[string]any{},
	}
	result := c.Correlate(e)
	if result.Multiplier != 1.0 {
		t.Errorf("zero PID should have multiplier 1.0, got %f", result.Multiplier)
	}
}
