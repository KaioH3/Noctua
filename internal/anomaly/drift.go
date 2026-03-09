package anomaly

import (
	"math"
	"sync"
)

type DriftMonitor struct {
	mu             sync.Mutex
	baselineMean   float64
	baselineStdDev float64
	recentScores   []float64
	windowSize     int
	driftThreshold float64
	idx            int
	full           bool
}

func NewDriftMonitor(windowSize int, threshold float64) *DriftMonitor {
	return &DriftMonitor{
		recentScores:   make([]float64, windowSize),
		windowSize:     windowSize,
		driftThreshold: threshold,
	}
}

// SetBaseline computes mean and stddev from initial training scores.
func (dm *DriftMonitor) SetBaseline(scores []float64) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if len(scores) == 0 {
		return
	}

	dm.baselineMean = mean(scores)
	dm.baselineStdDev = stddev(scores, dm.baselineMean)

	// Reset the sliding window
	dm.idx = 0
	dm.full = false
}

// Record adds a score to the sliding window.
func (dm *DriftMonitor) Record(score float64) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	dm.recentScores[dm.idx] = score
	dm.idx++
	if dm.idx >= dm.windowSize {
		dm.idx = 0
		dm.full = true
	}
}

// IsDrifted returns true if the recent score distribution has shifted
// significantly from the baseline.
func (dm *DriftMonitor) IsDrifted() bool {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if dm.baselineStdDev == 0 {
		return false
	}

	n := dm.windowSize
	if !dm.full {
		n = dm.idx
	}
	if n == 0 {
		return false
	}

	recentMean := mean(dm.recentScores[:n])
	shift := math.Abs(recentMean - dm.baselineMean)

	return shift > dm.driftThreshold*dm.baselineStdDev
}

// DriftMagnitude returns how many stddevs the recent mean has shifted.
func (dm *DriftMonitor) DriftMagnitude() float64 {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if dm.baselineStdDev == 0 {
		return 0
	}

	n := dm.windowSize
	if !dm.full {
		n = dm.idx
	}
	if n == 0 {
		return 0
	}

	recentMean := mean(dm.recentScores[:n])
	return math.Abs(recentMean-dm.baselineMean) / dm.baselineStdDev
}

func mean(data []float64) float64 {
	if len(data) == 0 {
		return 0
	}
	var sum float64
	for _, v := range data {
		sum += v
	}
	return sum / float64(len(data))
}

func stddev(data []float64, m float64) float64 {
	if len(data) < 2 {
		return 0
	}
	var sum float64
	for _, v := range data {
		d := v - m
		sum += d * d
	}
	return math.Sqrt(sum / float64(len(data)))
}
