package anomaly

import (
	"math/rand"
	"testing"
)

func TestFitAndScoreNormalPoints(t *testing.T) {
	forest := NewIsolationForest(100, 256)

	rng := rand.New(rand.NewSource(1))
	data := make([][]float64, 500)
	for i := range data {
		data[i] = []float64{rng.NormFloat64(), rng.NormFloat64()}
	}
	forest.Fit(data)

	// Normal point near center should have low anomaly score
	score := forest.Score([]float64{0.1, -0.2})
	if score >= 0.5 {
		t.Errorf("normal point scored %.4f, want < 0.5", score)
	}
}

func TestScoreOutlier(t *testing.T) {
	forest := NewIsolationForest(100, 256)

	rng := rand.New(rand.NewSource(1))
	data := make([][]float64, 500)
	for i := range data {
		data[i] = []float64{rng.NormFloat64(), rng.NormFloat64()}
	}
	forest.Fit(data)

	// Far outlier should have high anomaly score
	score := forest.Score([]float64{100.0, 100.0})
	if score <= 0.7 {
		t.Errorf("outlier scored %.4f, want > 0.7", score)
	}
}

func TestFitEmptyData(t *testing.T) {
	forest := NewIsolationForest(10, 32)
	forest.Fit(nil)
	if len(forest.Trees) != 0 {
		t.Errorf("expected no trees after fitting empty data, got %d", len(forest.Trees))
	}
}

func TestScoreWithNoTrees(t *testing.T) {
	forest := NewIsolationForest(10, 32)
	score := forest.Score([]float64{1.0, 2.0})
	if score != 0 {
		t.Errorf("expected 0 score with no trees, got %f", score)
	}
}

func TestFitSinglePoint(t *testing.T) {
	forest := NewIsolationForest(10, 32)
	forest.Fit([][]float64{{1.0, 2.0}})
	if len(forest.Trees) != 10 {
		t.Errorf("expected 10 trees, got %d", len(forest.Trees))
	}
}

func TestFitIdenticalFeatures(t *testing.T) {
	forest := NewIsolationForest(10, 32)
	data := make([][]float64, 100)
	for i := range data {
		data[i] = []float64{5.0, 5.0}
	}
	forest.Fit(data)
	// Should not panic; all points identical means leaf nodes
	score := forest.Score([]float64{5.0, 5.0})
	if score < 0 || score > 1 {
		t.Errorf("score out of [0,1] range: %f", score)
	}
}
