package correlator

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func newTestFeedbackStore(t *testing.T) *FeedbackStore {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "feedback.json")
	return &FeedbackStore{
		entries: make(map[string]*FeedbackEntry),
		path:    path,
		alpha:   2.0,
	}
}

func TestEffectiveWeightNoFP(t *testing.T) {
	fs := newTestFeedbackStore(t)
	// 0% false positive rate → full weight
	fs.entries["rule1"] = &FeedbackEntry{TotalEvents: 10, TruePositives: 10, FalsePositives: 0}

	w := fs.EffectiveWeight("rule1", 100.0)
	if w != 100.0 {
		t.Errorf("0%% FP: expected weight 100.0, got %f", w)
	}
}

func TestEffectiveWeightHalfFP(t *testing.T) {
	fs := newTestFeedbackStore(t)
	// 50% false positive rate → weight * (1-0.5)^2 = weight * 0.25
	fs.entries["rule1"] = &FeedbackEntry{TotalEvents: 10, TruePositives: 5, FalsePositives: 5}

	w := fs.EffectiveWeight("rule1", 100.0)
	expected := 100.0 * math.Pow(0.5, 2.0)
	if math.Abs(w-expected) > 0.01 {
		t.Errorf("50%% FP: expected weight %.2f, got %.2f", expected, w)
	}
}

func TestEffectiveWeightUnknownRule(t *testing.T) {
	fs := newTestFeedbackStore(t)
	w := fs.EffectiveWeight("unknown", 50.0)
	if w != 50.0 {
		t.Errorf("unknown rule: expected full weight 50.0, got %f", w)
	}
}

func TestPersistAndLoad(t *testing.T) {
	fs := newTestFeedbackStore(t)
	fs.RecordFeedback("entity1", "rule1", false)
	fs.RecordFeedback("entity2", "rule1", true)

	// Verify file was written
	data, err := os.ReadFile(fs.path)
	if err != nil {
		t.Fatalf("failed to read feedback file: %v", err)
	}

	var loaded map[string]*FeedbackEntry
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("failed to parse feedback JSON: %v", err)
	}

	entry, ok := loaded["rule1"]
	if !ok {
		t.Fatal("rule1 not found in persisted feedback")
	}
	if entry.TotalEvents != 2 || entry.FalsePositives != 1 || entry.TruePositives != 1 {
		t.Errorf("unexpected entry: %+v", entry)
	}
}

func TestLoadFromDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feedback.json")

	// Write some data
	data, _ := json.Marshal(map[string]*FeedbackEntry{
		"rule_x": {TotalEvents: 5, TruePositives: 3, FalsePositives: 2},
	})
	os.WriteFile(path, data, 0644)

	// Create store pointing to the same file
	fs := &FeedbackStore{
		entries: make(map[string]*FeedbackEntry),
		path:    path,
		alpha:   2.0,
	}
	fs.load()

	w := fs.EffectiveWeight("rule_x", 100.0)
	fpRate := 2.0 / 5.0
	expected := 100.0 * math.Pow(1-fpRate, 2.0)
	if math.Abs(w-expected) > 0.01 {
		t.Errorf("loaded rule_x: expected weight %.2f, got %.2f", expected, w)
	}
}
