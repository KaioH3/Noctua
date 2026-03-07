package sigma

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRulesValidDir(t *testing.T) {
	dir := t.TempDir()

	yamlContent := `
title: Test Rule
id: test-001
level: high
logsource:
  category: process_creation
detection:
  selection:
    ProcessName: evil
  condition: selection
`
	os.WriteFile(filepath.Join(dir, "test.yml"), []byte(yamlContent), 0644)

	rules, err := LoadRules(dir)
	if err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Title != "Test Rule" {
		t.Errorf("expected title 'Test Rule', got %q", rules[0].Title)
	}
	if rules[0].Level != "high" {
		t.Errorf("expected level 'high', got %q", rules[0].Level)
	}
}

func TestLoadRulesInvalidDir(t *testing.T) {
	rules, err := LoadRules("/nonexistent/path")
	if err != nil {
		t.Fatalf("LoadRules should not error on invalid dir, got: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules for invalid dir, got %d", len(rules))
	}
}

func TestLoadRulesSkipsInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "bad.yml"), []byte("{{{{invalid yaml"), 0644)
	os.WriteFile(filepath.Join(dir, "good.yml"), []byte(`
title: Good Rule
id: good-001
level: low
detection:
  selection:
    ProcessName: test
  condition: selection
`), 0644)

	rules, err := LoadRules(dir)
	if err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("expected 1 valid rule, got %d", len(rules))
	}
}

func TestExtractEmbeddedRules(t *testing.T) {
	tmpDir, err := ExtractEmbeddedRules()
	if err != nil {
		t.Fatalf("ExtractEmbeddedRules failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("failed to read tmpDir: %v", err)
	}

	if len(entries) != 20 {
		t.Errorf("expected 20 embedded rules, got %d", len(entries))
	}

	// Verify they're valid YAML that loads
	rules, err := LoadRules(tmpDir)
	if err != nil {
		t.Fatalf("LoadRules on embedded rules failed: %v", err)
	}
	if len(rules) != 20 {
		t.Errorf("expected 20 loaded rules, got %d", len(rules))
	}
}
