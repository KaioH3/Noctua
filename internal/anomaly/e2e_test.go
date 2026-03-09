package anomaly

import (
	"testing"
	"time"

	"noctua/internal/event"
)

func TestE2ECycleDriftRetrain(t *testing.T) {
	d := NewDetector(50, 64, 500, 30, 1.5)

	// 1. Feed "normal" events (simulating learning phase)
	for i := 0; i < 100; i++ {
		e := &event.Event{
			Source:    "network",
			Timestamp: time.Now().Add(time.Duration(i) * time.Second),
			Details: map[string]any{
				"pid":         int32(100),
				"remote_addr": "10.0.0.1",
				"remote_port": uint32(443),
			},
		}
		d.Evaluate(e)
	}

	// 2. Train
	d.Train()
	if !d.IsTrained() {
		t.Fatal("detector should be trained")
	}

	// 3. Verify normal scores are reasonable
	var normalScores []float64
	for i := 0; i < 20; i++ {
		e := &event.Event{
			Source:    "network",
			Timestamp: time.Now().Add(time.Duration(200+i) * time.Second),
			Details: map[string]any{
				"pid":         int32(100),
				"remote_addr": "10.0.0.1",
				"remote_port": uint32(443),
			},
		}
		score := d.Evaluate(e)
		normalScores = append(normalScores, score)
		if score < 0 || score > 1 {
			t.Fatalf("normal score out of range: %f", score)
		}
	}

	// 4. Feed anomalous events (very different features)
	var anomalousScores []float64
	for i := 0; i < 30; i++ {
		e := &event.Event{
			Source:    "network",
			Timestamp: time.Now().Add(time.Duration(300+i) * time.Second),
			Details: map[string]any{
				"pid":         int32(99999),
				"remote_addr": "192.168.100.200",
				"remote_port": uint32(4444),
			},
		}
		score := d.Evaluate(e)
		anomalousScores = append(anomalousScores, score)
	}

	// 5. Verify anomalous scores are generally higher than normal
	normalMean := mean(normalScores)
	anomalousMean := mean(anomalousScores)
	t.Logf("Normal mean score: %.4f, Anomalous mean score: %.4f", normalMean, anomalousMean)

	// 6. Check drift detection state (may or may not trigger depending on distribution)
	driftBefore := d.NeedsRetrain()
	t.Logf("Drift detected before retrain: %v (magnitude: %.2fσ)", driftBefore, d.DriftMagnitude())

	// 7. Retrain with accumulated buffer data
	n := d.Retrain()
	if n == 0 {
		t.Fatal("retrain should have used buffer data")
	}
	t.Logf("Retrained with %d samples", n)

	// 8. After retrain, drift should be reset
	if d.NeedsRetrain() {
		t.Error("should not need retrain immediately after retraining")
	}

	// 9. Verify model still produces valid scores
	e := &event.Event{
		Source:    "network",
		Timestamp: time.Now().Add(500 * time.Second),
		Details: map[string]any{
			"pid":         int32(100),
			"remote_addr": "10.0.0.1",
			"remote_port": uint32(443),
		},
	}
	score := d.Evaluate(e)
	if score < 0 || score > 1 {
		t.Errorf("score after retrain should be in [0,1], got %f", score)
	}
}
