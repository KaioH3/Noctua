package sigma

import (
	"embed"
	"os"
	"path/filepath"
)

//go:embed rules/*.yml
var embeddedRules embed.FS

// ExtractEmbeddedRules extracts built-in Sigma rules to a temp directory
// and returns the path. Caller should clean up with os.RemoveAll when done.
func ExtractEmbeddedRules() (string, error) {
	tmpDir, err := os.MkdirTemp("", "noctua-sigma-*")
	if err != nil {
		return "", err
	}

	entries, err := embeddedRules.ReadDir("rules")
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := embeddedRules.ReadFile("rules/" + entry.Name())
		if err != nil {
			continue
		}
		os.WriteFile(filepath.Join(tmpDir, entry.Name()), data, 0644)
	}

	return tmpDir, nil
}
