package anomaly

import (
	"testing"
	"time"

	"noctua/internal/event"
)

func TestExtractReturns6Floats(t *testing.T) {
	fe := NewFeatureExtractor()
	e := event.Event{
		Source:    "network",
		Timestamp: time.Now(),
		Details: map[string]any{
			"pid":         int32(100),
			"remote_addr": "1.2.3.4",
			"remote_port": uint32(443),
		},
	}
	vec := fe.Extract(e)
	if len(vec) != 6 {
		t.Fatalf("expected 6 features, got %d", len(vec))
	}
}

func TestExtractNetworkCountsUp(t *testing.T) {
	fe := NewFeatureExtractor()
	now := time.Now()

	for i := 0; i < 5; i++ {
		e := event.Event{
			Source:    "network",
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Details: map[string]any{
				"pid":         int32(100),
				"remote_addr": "1.2.3.4",
				"remote_port": uint32(443),
			},
		}
		fe.Extract(e)
	}

	// One more extract to read current state
	vec := fe.Extract(event.Event{
		Source:    "network",
		Timestamp: now.Add(5 * time.Second),
		Details: map[string]any{
			"pid":         int32(100),
			"remote_addr": "1.2.3.4",
			"remote_port": uint32(443),
		},
	})

	connPerMin := vec[0]
	if connPerMin <= 0 {
		t.Errorf("expected connPerMin > 0, got %f", connPerMin)
	}
}

func TestPruneRemovesOldEvents(t *testing.T) {
	fe := NewFeatureExtractor()
	old := time.Now().Add(-10 * time.Minute)

	fe.Extract(event.Event{
		Source:    "process",
		Timestamp: old,
		Details:   map[string]any{"pid": int32(1)},
	})

	// Extract with current time should have pruned the old event
	vec := fe.Extract(event.Event{
		Source:    "process",
		Timestamp: time.Now(),
		Details:   map[string]any{"pid": int32(2)},
	})

	procPerMin := vec[4]
	// Only 1 recent process event, old one should be pruned
	if procPerMin > 1 {
		t.Errorf("expected ~1 proc/min after pruning, got %f", procPerMin)
	}
}
