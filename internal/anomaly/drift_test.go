package anomaly

import (
	"testing"
)

func TestDriftMonitorNoDrift(t *testing.T) {
	dm := NewDriftMonitor(100, 2.0)

	// Baseline: scores around 0.5
	baseline := make([]float64, 200)
	for i := range baseline {
		baseline[i] = 0.5 + float64(i%10)*0.01
	}
	dm.SetBaseline(baseline)

	// Record similar scores
	for i := 0; i < 100; i++ {
		dm.Record(0.5 + float64(i%10)*0.01)
	}

	if dm.IsDrifted() {
		t.Error("expected no drift with similar scores")
	}
}

func TestDriftMonitorDetectsDrift(t *testing.T) {
	dm := NewDriftMonitor(50, 2.0)

	// Baseline: scores around 0.3
	baseline := make([]float64, 100)
	for i := range baseline {
		baseline[i] = 0.3 + float64(i%5)*0.01
	}
	dm.SetBaseline(baseline)

	// Record much higher scores — should trigger drift
	for i := 0; i < 50; i++ {
		dm.Record(0.9)
	}

	if !dm.IsDrifted() {
		t.Error("expected drift with significantly different scores")
	}
}

func TestDriftMonitorReset(t *testing.T) {
	dm := NewDriftMonitor(50, 2.0)

	// Baseline: low scores with some variance
	baseline := make([]float64, 100)
	for i := range baseline {
		baseline[i] = 0.2 + float64(i%10)*0.005
	}
	dm.SetBaseline(baseline)

	// Record high scores to cause drift
	for i := 0; i < 50; i++ {
		dm.Record(0.9)
	}

	if !dm.IsDrifted() {
		t.Fatal("expected drift before reset")
	}

	// Reset baseline to match new behavior (with some variance)
	newBaseline := make([]float64, 100)
	for i := range newBaseline {
		newBaseline[i] = 0.9 + float64(i%10)*0.005
	}
	dm.SetBaseline(newBaseline)

	// Record scores matching new baseline
	for i := 0; i < 50; i++ {
		dm.Record(0.9 + float64(i%10)*0.005)
	}

	if dm.IsDrifted() {
		t.Error("expected no drift after reset with matching baseline")
	}
}

func TestDriftMonitorEmptyWindow(t *testing.T) {
	dm := NewDriftMonitor(100, 2.0)

	baseline := make([]float64, 50)
	for i := range baseline {
		baseline[i] = 0.5
	}
	dm.SetBaseline(baseline)

	// No scores recorded yet
	if dm.IsDrifted() {
		t.Error("empty window should not report drift")
	}
}

func TestDriftMagnitude(t *testing.T) {
	dm := NewDriftMonitor(50, 2.0)

	baseline := make([]float64, 100)
	for i := range baseline {
		baseline[i] = 0.3
	}
	dm.SetBaseline(baseline)

	for i := 0; i < 50; i++ {
		dm.Record(0.9)
	}

	mag := dm.DriftMagnitude()
	if mag <= 0 {
		t.Errorf("expected positive drift magnitude, got %f", mag)
	}
}
