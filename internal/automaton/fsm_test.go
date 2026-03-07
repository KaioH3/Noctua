package automaton

import (
	"testing"
	"time"

	"noctua/internal/config"
	"noctua/internal/event"
)

func newTestAutomaton() *Automaton {
	return New(config.Thresholds{
		Watching:    15,
		Suspicious:  35,
		Threat:      65,
		Blocked:     90,
		DecayPerMin: 5,
	})
}

func TestTransitionCleanToWatching(t *testing.T) {
	a := newTestAutomaton()
	a.Process(event.Event{
		EntityID: "e1",
		Source:   "process",
		Score:    20,
		Timestamp: time.Now(),
		Details:  map[string]any{},
	})
	ent := a.GetEntity("e1")
	if ent == nil {
		t.Fatal("entity not found")
	}
	if ent.State != Watching {
		t.Errorf("expected Watching, got %s", ent.State)
	}
}

func TestTransitionToSuspicious(t *testing.T) {
	a := newTestAutomaton()
	a.Process(event.Event{
		EntityID: "e1", Source: "process", Score: 40,
		Timestamp: time.Now(), Details: map[string]any{},
	})
	ent := a.GetEntity("e1")
	if ent.State != Suspicious {
		t.Errorf("expected Suspicious, got %s", ent.State)
	}
}

func TestTransitionToThreat(t *testing.T) {
	a := newTestAutomaton()
	a.Process(event.Event{
		EntityID: "e1", Source: "process", Score: 70,
		Timestamp: time.Now(), Details: map[string]any{},
	})
	ent := a.GetEntity("e1")
	if ent.State != Threat {
		t.Errorf("expected Threat, got %s", ent.State)
	}
}

func TestTransitionToBlocked(t *testing.T) {
	a := newTestAutomaton()
	a.Process(event.Event{
		EntityID: "e1", Source: "process", Score: 100,
		Timestamp: time.Now(), Details: map[string]any{},
	})
	ent := a.GetEntity("e1")
	if ent.State != Blocked {
		t.Errorf("expected Blocked, got %s", ent.State)
	}
}

func TestScoreAccumulates(t *testing.T) {
	a := newTestAutomaton()
	now := time.Now()
	a.Process(event.Event{
		EntityID: "e1", Source: "process", Score: 20,
		Timestamp: now, Details: map[string]any{},
	})
	a.Process(event.Event{
		EntityID: "e1", Source: "process", Score: 20,
		Timestamp: now.Add(1 * time.Second), Details: map[string]any{},
	})
	ent := a.GetEntity("e1")
	if ent.Score != 40 {
		t.Errorf("expected score 40, got %f", ent.Score)
	}
	if ent.State != Suspicious {
		t.Errorf("expected Suspicious after 40, got %s", ent.State)
	}
}

func TestDecayReducesScore(t *testing.T) {
	a := newTestAutomaton()
	a.Process(event.Event{
		EntityID: "e1", Source: "process", Score: 50,
		Timestamp: time.Now(), Details: map[string]any{},
	})

	a.Decay(1 * time.Minute) // decay 5 per minute
	ent := a.GetEntity("e1")
	if ent.Score != 45 {
		t.Errorf("expected score 45 after 1min decay, got %f", ent.Score)
	}
}

func TestDecayDoesNotGoBelowZero(t *testing.T) {
	a := newTestAutomaton()
	a.Process(event.Event{
		EntityID: "e1", Source: "process", Score: 2,
		Timestamp: time.Now(), Details: map[string]any{},
	})

	a.Decay(1 * time.Minute)
	ent := a.GetEntity("e1")
	if ent == nil {
		// Entity may have been removed if score=0 and old enough
		return
	}
	if ent.Score < 0 {
		t.Errorf("score should not go below 0, got %f", ent.Score)
	}
}

func TestBlockedDoesNotDecay(t *testing.T) {
	a := newTestAutomaton()
	a.Process(event.Event{
		EntityID: "e1", Source: "process", Score: 100,
		Timestamp: time.Now(), Details: map[string]any{},
	})

	a.Decay(10 * time.Minute)
	ent := a.GetEntity("e1")
	if ent.Score != 100 {
		t.Errorf("blocked entity should not decay, score %f", ent.Score)
	}
}

func TestEntityRemovedAfterZeroScore(t *testing.T) {
	a := newTestAutomaton()
	old := time.Now().Add(-15 * time.Minute)
	a.Process(event.Event{
		EntityID: "e1", Source: "process", Score: 1,
		Timestamp: old, Details: map[string]any{},
	})

	// Decay enough to zero the score
	a.Decay(1 * time.Minute)

	ent := a.GetEntity("e1")
	if ent != nil {
		t.Errorf("entity with score 0 and last event >10min ago should be removed, got score %f", ent.Score)
	}
}

func TestTransitionChannelReceivesEvents(t *testing.T) {
	a := newTestAutomaton()
	a.Process(event.Event{
		EntityID: "e1", Source: "process", Score: 20,
		Timestamp: time.Now(), Details: map[string]any{},
	})

	select {
	case tr := <-a.Transitions():
		if tr.From != Clean || tr.To != Watching {
			t.Errorf("expected Clean->Watching, got %s->%s", tr.From, tr.To)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no transition received")
	}
}

func TestSnapshot(t *testing.T) {
	a := newTestAutomaton()
	a.Process(event.Event{
		EntityID: "e1", Source: "process", Score: 20,
		Timestamp: time.Now(), Details: map[string]any{},
	})
	a.Process(event.Event{
		EntityID: "e2", Source: "network", Score: 40,
		Timestamp: time.Now(), Details: map[string]any{},
	})

	snap := a.Snapshot()
	if len(snap) != 2 {
		t.Errorf("expected 2 entities in snapshot, got %d", len(snap))
	}
}

func TestStateString(t *testing.T) {
	tests := []struct {
		s    State
		want string
	}{
		{Clean, "CLEAN"},
		{Watching, "WATCHING"},
		{Suspicious, "SUSPICIOUS"},
		{Threat, "THREAT"},
		{Blocked, "BLOCKED"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("State(%d).String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}
