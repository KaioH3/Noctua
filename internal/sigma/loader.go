package sigma

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Rule struct {
	Title     string                 `yaml:"title"`
	ID        string                 `yaml:"id"`
	Status    string                 `yaml:"status"`
	Level     string                 `yaml:"level"`
	Logsource Logsource              `yaml:"logsource"`
	Detection map[string]any         `yaml:"detection"`
	Tags      []string               `yaml:"tags"`
}

type Logsource struct {
	Category string `yaml:"category"`
	Product  string `yaml:"product"`
}

func LoadRules(dirs ...string) ([]Rule, error) {
	var rules []Rule

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".yml" {
				continue
			}

			path := filepath.Join(dir, entry.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}

			var rule Rule
			if err := yaml.Unmarshal(data, &rule); err != nil {
				fmt.Printf("[sigma] warning: failed to parse %s: %v\n", path, err)
				continue
			}

			if rule.Title != "" && rule.Detection != nil {
				rules = append(rules, rule)
			}
		}
	}

	return rules, nil
}

func LevelToBonus(level string) float64 {
	switch level {
	case "critical":
		return 60
	case "high":
		return 40
	case "medium":
		return 25
	case "low":
		return 10
	default:
		return 5
	}
}
