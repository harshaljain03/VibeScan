package input

import (
	"errors"
	"os"
	"strings"
)

// ParseTargets normalizes and deduplicates targets from a single input string.
func ParseTargets(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("target input is empty")
	}

	items, err := readTargets(raw)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	result := make([]string, 0, len(items))
	for _, item := range items {
		for _, candidate := range splitCandidates(item) {
			if shouldIgnore(candidate) {
				continue
			}

			normalized := normalizeTarget(candidate)
			if normalized == "" {
				continue
			}

			if _, exists := seen[normalized]; exists {
				continue
			}
			seen[normalized] = struct{}{}
			result = append(result, normalized)
		}
	}

	if len(result) == 0 {
		return nil, errors.New("no valid targets found")
	}

	return result, nil
}

func readTargets(raw string) ([]string, error) {
	if isFilePath(raw) {
		payload, err := os.ReadFile(raw)
		if err != nil {
			return nil, err
		}
		lines := strings.Split(strings.ReplaceAll(string(payload), "\r\n", "\n"), "\n")
		return lines, nil
	}

	if strings.Contains(raw, ",") {
		return strings.Split(raw, ","), nil
	}

	return []string{raw}, nil
}

func isFilePath(raw string) bool {
	info, err := os.Stat(raw)
	if err != nil {
		return false
	}

	return !info.IsDir()
}

func splitCandidates(item string) []string {
	if strings.Contains(item, ",") {
		return strings.Split(item, ",")
	}
	return []string{item}
}

func shouldIgnore(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return true
	}
	if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
		return true
	}
	return false
}

func normalizeTarget(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}

	if idx := strings.Index(trimmed, "://"); idx != -1 {
		trimmed = trimmed[idx+3:]
	}

	trimmed = strings.TrimRight(trimmed, "/")

	return strings.TrimSpace(trimmed)
}
