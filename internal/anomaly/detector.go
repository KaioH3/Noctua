package anomaly

import (
	"sync"

	"noctua/internal/event"
)

type Detector struct {
	mu        sync.Mutex
	forest    *IsolationForest
	extractor *FeatureExtractor
	training  [][]float64
	trained   bool
	numTrees  int
	sampleSz  int
	minSamples int
}

func NewDetector(numTrees, sampleSize int) *Detector {
	return &Detector{
		forest:     NewIsolationForest(numTrees, sampleSize),
		extractor:  NewFeatureExtractor(),
		numTrees:   numTrees,
		sampleSz:   sampleSize,
		minSamples: sampleSize,
	}
}

func (d *Detector) Train() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.training) < 10 {
		return
	}

	d.forest = NewIsolationForest(d.numTrees, d.sampleSz)
	d.forest.Fit(d.training)
	d.trained = true
}

func (d *Detector) Evaluate(e *event.Event) float64 {
	features := d.extractor.Extract(*e)

	d.mu.Lock()
	if !d.trained {
		d.training = append(d.training, features)
		d.mu.Unlock()
		return 0
	}
	d.mu.Unlock()

	score := d.forest.Score(features)
	e.AnomalyScore = score

	var bonus float64
	switch {
	case score > 0.95:
		bonus = 50
	case score > 0.85:
		bonus = 30
	case score > 0.7:
		bonus = 15
	}

	e.Score += bonus
	return score
}

func (d *Detector) IsTrained() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.trained
}

func (d *Detector) TrainingSamples() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.training)
}
