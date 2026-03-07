package anomaly

import (
	"testing"
	"time"

	"noctua/internal/event"
)

func TestDetectorTrainAndEvaluate(t *testing.T) {
	d := NewDetector(10, 32)

	// Feed training data (needs at least 10 samples)
	for i := 0; i < 50; i++ {
		e := &event.Event{
			Source:    "network",
			Timestamp: time.Now().Add(time.Duration(i) * time.Second),
			Details: map[string]any{
				"pid":         int32(100),
				"remote_addr": "1.2.3.4",
				"remote_port": uint32(443),
			},
		}
		score := d.Evaluate(e)
		if score != 0 {
			t.Errorf("before training, score should be 0, got %f", score)
		}
	}

	if d.IsTrained() {
		t.Error("should not be trained before Train()")
	}

	d.Train()

	if !d.IsTrained() {
		t.Error("should be trained after Train()")
	}

	// Evaluate after training should return non-zero score
	e := &event.Event{
		Source:    "network",
		Timestamp: time.Now().Add(60 * time.Second),
		Details: map[string]any{
			"pid":         int32(100),
			"remote_addr": "1.2.3.4",
			"remote_port": uint32(443),
		},
	}
	score := d.Evaluate(e)
	if score < 0 || score > 1 {
		t.Errorf("score should be in [0,1], got %f", score)
	}
}

func TestDetectorTrainingSamples(t *testing.T) {
	d := NewDetector(10, 32)
	if d.TrainingSamples() != 0 {
		t.Errorf("expected 0 training samples initially, got %d", d.TrainingSamples())
	}

	e := &event.Event{
		Source:    "process",
		Timestamp: time.Now(),
		Details:   map[string]any{"pid": int32(1)},
	}
	d.Evaluate(e)

	if d.TrainingSamples() != 1 {
		t.Errorf("expected 1 training sample, got %d", d.TrainingSamples())
	}
}

func TestDetectorTrainNotEnoughSamples(t *testing.T) {
	d := NewDetector(10, 32)

	// Only 5 samples — not enough for training (min 10)
	for i := 0; i < 5; i++ {
		e := &event.Event{
			Source:    "process",
			Timestamp: time.Now(),
			Details:   map[string]any{"pid": int32(1)},
		}
		d.Evaluate(e)
	}

	d.Train()
	if d.IsTrained() {
		t.Error("should not be trained with < 10 samples")
	}
}
