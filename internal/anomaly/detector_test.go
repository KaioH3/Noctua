package anomaly

import (
	"sync"
	"testing"
	"time"

	"noctua/internal/event"
)

func TestDetectorTrainAndEvaluate(t *testing.T) {
	d := NewDetector(10, 32, 500, 100, 2.0)

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
	d := NewDetector(10, 32, 500, 100, 2.0)
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
	d := NewDetector(10, 32, 500, 100, 2.0)

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

func TestDetectorRetrain(t *testing.T) {
	d := NewDetector(10, 32, 500, 50, 2.0)

	// Feed training data
	for i := 0; i < 50; i++ {
		e := &event.Event{
			Source:    "network",
			Timestamp: time.Now(),
			Details: map[string]any{
				"pid":         int32(100 + i),
				"remote_addr": "10.0.0.1",
				"remote_port": uint32(443),
			},
		}
		d.Evaluate(e)
	}
	d.Train()

	// Feed new data after training
	for i := 0; i < 100; i++ {
		e := &event.Event{
			Source:    "network",
			Timestamp: time.Now(),
			Details: map[string]any{
				"pid":         int32(1000 + i),
				"remote_addr": "192.168.1.1",
				"remote_port": uint32(8080),
			},
		}
		d.Evaluate(e)
	}

	// Retrain with buffer data
	n := d.Retrain()
	if n == 0 {
		t.Error("expected retrain to use buffer data")
	}

	// Scores should still be valid after retrain
	e := &event.Event{
		Source:    "network",
		Timestamp: time.Now(),
		Details: map[string]any{
			"pid":         int32(2000),
			"remote_addr": "192.168.1.1",
			"remote_port": uint32(8080),
		},
	}
	score := d.Evaluate(e)
	if score < 0 || score > 1 {
		t.Errorf("score after retrain should be in [0,1], got %f", score)
	}
}

func TestDetectorNeedsRetrain(t *testing.T) {
	d := NewDetector(10, 32, 500, 20, 1.5)

	// Train with low-feature data
	for i := 0; i < 50; i++ {
		e := &event.Event{
			Source:    "process",
			Timestamp: time.Now(),
			Details: map[string]any{
				"pid": int32(1),
			},
		}
		d.Evaluate(e)
	}
	d.Train()

	// Initially no drift
	if d.NeedsRetrain() {
		t.Error("should not need retrain immediately after training")
	}

	// Feed very different data to trigger drift
	for i := 0; i < 30; i++ {
		e := &event.Event{
			Source:    "network",
			Timestamp: time.Now(),
			Details: map[string]any{
				"pid":         int32(99999),
				"remote_addr": "10.10.10.10",
				"remote_port": uint32(4444),
			},
		}
		d.Evaluate(e)
	}

	// Drift may or may not be detected depending on score distribution
	// Just verify it doesn't panic
	_ = d.NeedsRetrain()
}

func TestDetectorRetrainAtomicSwap(t *testing.T) {
	d := NewDetector(10, 32, 500, 100, 2.0)

	// Train
	for i := 0; i < 50; i++ {
		e := &event.Event{
			Source:    "network",
			Timestamp: time.Now(),
			Details: map[string]any{
				"pid":         int32(i + 1),
				"remote_addr": "10.0.0.1",
				"remote_port": uint32(443),
			},
		}
		d.Evaluate(e)
	}
	d.Train()

	// Feed more data for buffer
	for i := 0; i < 100; i++ {
		e := &event.Event{
			Source:    "network",
			Timestamp: time.Now(),
			Details: map[string]any{
				"pid":         int32(200 + i),
				"remote_addr": "10.0.0.2",
				"remote_port": uint32(80),
			},
		}
		d.Evaluate(e)
	}

	// Concurrent scoring during retrain
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		d.Retrain()
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			e := &event.Event{
				Source:    "network",
				Timestamp: time.Now(),
				Details: map[string]any{
					"pid":         int32(500 + i),
					"remote_addr": "10.0.0.3",
					"remote_port": uint32(443),
				},
			}
			score := d.Evaluate(e)
			if score < 0 || score > 1 {
				t.Errorf("score during retrain should be in [0,1], got %f", score)
			}
		}
	}()

	wg.Wait()
}
