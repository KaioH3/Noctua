package correlator

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sync"
)

type FeedbackEntry struct {
	TotalEvents    int `json:"total_events"`
	TruePositives  int `json:"true_positives"`
	FalsePositives int `json:"false_positives"`
}

type FeedbackStore struct {
	mu      sync.RWMutex
	entries map[string]*FeedbackEntry // keyed by rule/pattern name
	path    string
	alpha   float64
}

func NewFeedbackStore() *FeedbackStore {
	homeDir, _ := os.UserHomeDir()
	path := filepath.Join(homeDir, ".noctua", "feedback.json")
	os.MkdirAll(filepath.Dir(path), 0755)

	fs := &FeedbackStore{
		entries: make(map[string]*FeedbackEntry),
		path:    path,
		alpha:   2.0,
	}
	fs.load()
	return fs
}

func (fs *FeedbackStore) RecordFeedback(entityID string, ruleName string, isFalsePositive bool) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	entry, ok := fs.entries[ruleName]
	if !ok {
		entry = &FeedbackEntry{}
		fs.entries[ruleName] = entry
	}

	entry.TotalEvents++
	if isFalsePositive {
		entry.FalsePositives++
	} else {
		entry.TruePositives++
	}

	fs.save()
}

// EffectiveWeight returns the adjusted weight for a rule.
// Formula: effective_weight = base_weight * (1 - fp_rate)^alpha
func (fs *FeedbackStore) EffectiveWeight(ruleName string, baseWeight float64) float64 {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	entry, ok := fs.entries[ruleName]
	if !ok || entry.TotalEvents == 0 {
		return baseWeight
	}

	fpRate := float64(entry.FalsePositives) / float64(entry.TotalEvents)
	return baseWeight * math.Pow(1-fpRate, fs.alpha)
}

func (fs *FeedbackStore) Stats() map[string]*FeedbackEntry {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	result := make(map[string]*FeedbackEntry, len(fs.entries))
	for k, v := range fs.entries {
		copy := *v
		result[k] = &copy
	}
	return result
}

func (fs *FeedbackStore) load() {
	data, err := os.ReadFile(fs.path)
	if err != nil {
		return
	}
	json.Unmarshal(data, &fs.entries)
}

func (fs *FeedbackStore) save() {
	data, err := json.MarshalIndent(fs.entries, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(fs.path, data, 0644)
}
