package sigma

import (
	"fmt"
	"regexp"
	"strings"

	"noctua/internal/event"
)

// Field mapping: Sigma field names to event.Details keys
var fieldMapping = map[string]string{
	"Image":           "exe",
	"CommandLine":     "cmdline",
	"ParentImage":     "parent_exe",
	"User":            "user",
	"DestinationIp":   "remote_addr",
	"DestinationPort": "remote_port",
	"SourcePort":      "local_port",
	"TargetFilename":  "path",
	"ProcessName":     "name",
}

// categoryMapping: Sigma logsource.category to event.Source
var categoryMapping = map[string]string{
	"process_creation":    "process",
	"network_connection":  "network",
	"file_event":          "filesystem",
}

type Engine struct {
	rules []Rule
}

func NewEngine(rules []Rule) *Engine {
	return &Engine{rules: rules}
}

func (eng *Engine) Evaluate(e *event.Event) {
	for _, rule := range eng.rules {
		if !eng.sourceMatches(rule, e) {
			continue
		}
		if Match(rule, e) {
			e.SigmaRules = append(e.SigmaRules, rule.Title)
			e.Score += LevelToBonus(rule.Level)
		}
	}
}

func (eng *Engine) sourceMatches(rule Rule, e *event.Event) bool {
	if rule.Logsource.Category == "" {
		return true
	}
	expectedSource, ok := categoryMapping[rule.Logsource.Category]
	if !ok {
		return true
	}
	return expectedSource == e.Source
}

func (eng *Engine) RuleCount() int {
	return len(eng.rules)
}

func Match(rule Rule, e *event.Event) bool {
	detection := rule.Detection
	if detection == nil {
		return false
	}

	condition, _ := detection["condition"].(string)
	if condition == "" {
		condition = "selection"
	}

	return evaluateCondition(condition, detection, e)
}

func evaluateCondition(condition string, detection map[string]any, e *event.Event) bool {
	condition = strings.TrimSpace(condition)

	// Handle NOT
	if strings.HasPrefix(condition, "not ") {
		inner := strings.TrimPrefix(condition, "not ")
		return !evaluateCondition(inner, detection, e)
	}

	// Handle AND
	if parts := splitOutsideParens(condition, " and "); len(parts) > 1 {
		for _, part := range parts {
			if !evaluateCondition(part, detection, e) {
				return false
			}
		}
		return true
	}

	// Handle OR
	if parts := splitOutsideParens(condition, " or "); len(parts) > 1 {
		for _, part := range parts {
			if evaluateCondition(part, detection, e) {
				return true
			}
		}
		return false
	}

	// Handle parentheses
	if strings.HasPrefix(condition, "(") && strings.HasSuffix(condition, ")") {
		return evaluateCondition(condition[1:len(condition)-1], detection, e)
	}

	// Handle "1 of selection*"
	if strings.HasPrefix(condition, "1 of ") {
		prefix := strings.TrimSuffix(strings.TrimPrefix(condition, "1 of "), "*")
		for key, val := range detection {
			if key == "condition" {
				continue
			}
			if strings.HasPrefix(key, prefix) {
				if matchSelection(val, e) {
					return true
				}
			}
		}
		return false
	}

	// Handle "all of selection*"
	if strings.HasPrefix(condition, "all of ") {
		prefix := strings.TrimSuffix(strings.TrimPrefix(condition, "all of "), "*")
		matched := false
		for key, val := range detection {
			if key == "condition" {
				continue
			}
			if strings.HasPrefix(key, prefix) {
				matched = true
				if !matchSelection(val, e) {
					return false
				}
			}
		}
		return matched
	}

	// Direct selection reference
	if sel, ok := detection[condition]; ok {
		return matchSelection(sel, e)
	}

	return false
}

func matchSelection(sel any, e *event.Event) bool {
	switch v := sel.(type) {
	case map[string]any:
		return matchFieldMap(v, e)
	case []any:
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				if matchFieldMap(m, e) {
					return true
				}
			}
		}
		return false
	default:
		return false
	}
}

func matchFieldMap(fields map[string]any, e *event.Event) bool {
	for sigmaField, expectedVal := range fields {
		// Handle field modifiers
		field, modifier := parseSigmaField(sigmaField)

		// Map Sigma field to event detail key
		detailKey := field
		if mapped, ok := fieldMapping[field]; ok {
			detailKey = mapped
		}

		actualVal := e.Details[detailKey]
		if actualVal == nil {
			// Also check in event fields directly
			switch strings.ToLower(detailKey) {
			case "source":
				actualVal = e.Source
			case "kind":
				actualVal = e.Kind
			default:
				return false
			}
		}

		if !matchValue(actualVal, expectedVal, modifier) {
			return false
		}
	}
	return true
}

func parseSigmaField(field string) (string, string) {
	parts := strings.SplitN(field, "|", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return field, ""
}

func matchValue(actual any, expected any, modifier string) bool {
	actualStr := fmt.Sprintf("%v", actual)

	switch v := expected.(type) {
	case string:
		return matchString(actualStr, v, modifier)
	case []any:
		for _, item := range v {
			itemStr := fmt.Sprintf("%v", item)
			if matchString(actualStr, itemStr, modifier) {
				return true
			}
		}
		return false
	case int, int64, float64:
		expectedStr := fmt.Sprintf("%v", v)
		return actualStr == expectedStr
	default:
		return false
	}
}

func matchString(actual, pattern, modifier string) bool {
	actual = strings.ToLower(actual)
	pattern = strings.ToLower(pattern)

	switch modifier {
	case "contains":
		return strings.Contains(actual, pattern)
	case "startswith":
		return strings.HasPrefix(actual, pattern)
	case "endswith":
		return strings.HasSuffix(actual, pattern)
	case "re":
		matched, err := regexp.MatchString("(?i)"+pattern, actual)
		return err == nil && matched
	default:
		// Default: exact match or wildcard
		if strings.Contains(pattern, "*") {
			return matchWildcard(actual, pattern)
		}
		return actual == pattern
	}
}

func matchWildcard(s, pattern string) bool {
	if pattern == "*" {
		return true
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 0 {
		return s == pattern
	}

	pos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(s[pos:], part)
		if idx < 0 {
			return false
		}
		if i == 0 && !strings.HasPrefix(pattern, "*") && idx != 0 {
			return false
		}
		pos += idx + len(part)
	}

	if !strings.HasSuffix(pattern, "*") {
		return pos == len(s)
	}
	return true
}

func splitOutsideParens(s, sep string) []string {
	depth := 0
	var parts []string
	last := 0
	for i := 0; i <= len(s)-len(sep); i++ {
		if s[i] == '(' {
			depth++
		} else if s[i] == ')' {
			depth--
		} else if depth == 0 && s[i:i+len(sep)] == sep {
			parts = append(parts, s[last:i])
			last = i + len(sep)
			i += len(sep) - 1
		}
	}
	parts = append(parts, s[last:])
	if len(parts) <= 1 {
		return nil
	}
	return parts
}
