package anomaly

import (
	"sync"
	"sync/atomic"

	"noctua/internal/event"
)

type Detector struct {
	mu        sync.Mutex
	forest    atomic.Pointer[IsolationForest]
	extractor *FeatureExtractor
	training  [][]float64
	trained   bool
	numTrees  int
	sampleSz  int
	minSamples int

	// Circular buffer for retraining
	buffer    [][]float64
	bufIdx    int
	bufFull   bool
	maxBuffer int

	// Drift detection
	drift *DriftMonitor
}

func NewDetector(numTrees, sampleSize, maxBuffer, driftWindowSize int, driftThreshold float64) *Detector {
	f := NewIsolationForest(numTrees, sampleSize)
	d := &Detector{
		extractor:  NewFeatureExtractor(),
		numTrees:   numTrees,
		sampleSz:   sampleSize,
		minSamples: sampleSize,
		maxBuffer:  maxBuffer,
		buffer:     make([][]float64, maxBuffer),
		drift:      NewDriftMonitor(driftWindowSize, driftThreshold),
	}
	d.forest.Store(f)
	return d
}

func (d *Detector) Train() {
	d.mu.Lock()

	if len(d.training) < 10 {
		d.mu.Unlock()
		return
	}

	data := make([][]float64, len(d.training))
	copy(data, d.training)
	d.mu.Unlock()

	f := NewIsolationForest(d.numTrees, d.sampleSz)
	f.Fit(data)

	// Compute baseline scores for drift detection
	scores := make([]float64, len(data))
	for i, point := range data {
		scores[i] = f.Score(point)
	}
	d.drift.SetBaseline(scores)

	// Seed the circular buffer with training data
	d.mu.Lock()
	d.bufIdx = 0
	d.bufFull = false
	for _, point := range data {
		d.buffer[d.bufIdx] = point
		d.bufIdx++
		if d.bufIdx >= d.maxBuffer {
			d.bufIdx = 0
			d.bufFull = true
		}
	}
	d.trained = true
	d.mu.Unlock()

	d.forest.Store(f)
}

func (d *Detector) Evaluate(e *event.Event) float64 {
	features := d.extractor.Extract(*e)

	d.mu.Lock()
	if !d.trained {
		d.training = append(d.training, features)
		d.mu.Unlock()
		return 0
	}

	// Add to circular buffer
	d.buffer[d.bufIdx] = features
	d.bufIdx++
	if d.bufIdx >= d.maxBuffer {
		d.bufIdx = 0
		d.bufFull = true
	}
	d.mu.Unlock()

	f := d.forest.Load()
	score := f.Score(features)
	e.AnomalyScore = score

	// Record in drift monitor
	d.drift.Record(score)

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

// NeedsRetrain returns true if score drift has been detected.
func (d *Detector) NeedsRetrain() bool {
	return d.drift.IsDrifted()
}

// DriftMagnitude returns the current drift in standard deviations.
func (d *Detector) DriftMagnitude() float64 {
	return d.drift.DriftMagnitude()
}

// Retrain rebuilds the isolation forest from the circular buffer
// and resets the drift baseline.
func (d *Detector) Retrain() int {
	d.mu.Lock()
	var data [][]float64
	if d.bufFull {
		data = make([][]float64, d.maxBuffer)
		copy(data, d.buffer)
	} else {
		data = make([][]float64, d.bufIdx)
		copy(data, d.buffer[:d.bufIdx])
	}
	d.mu.Unlock()

	if len(data) < 10 {
		return 0
	}

	f := NewIsolationForest(d.numTrees, d.sampleSz)
	f.Fit(data)

	// Recompute baseline scores
	scores := make([]float64, len(data))
	for i, point := range data {
		scores[i] = f.Score(point)
	}
	d.drift.SetBaseline(scores)

	// Atomic swap
	d.forest.Store(f)

	return len(data)
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
