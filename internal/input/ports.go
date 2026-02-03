package input

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ParsePorts parses a comma-separated port specification that may include ranges.
func ParsePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, errors.New("port specification is empty")
	}

	parts := strings.Split(spec, ",")
	seen := make(map[int]struct{})
	ports := make([]int, 0)

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			start, err := parsePortValue(rangeParts[0])
			if err != nil {
				return nil, err
			}
			end, err := parsePortValue(rangeParts[1])
			if err != nil {
				return nil, err
			}
			if start > end {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			for port := start; port <= end; port++ {
				if _, exists := seen[port]; exists {
					continue
				}
				seen[port] = struct{}{}
				ports = append(ports, port)
			}
			continue
		}

		port, err := parsePortValue(part)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}

	if len(ports) == 0 {
		return nil, errors.New("no valid ports found")
	}

	return ports, nil
}

func parsePortValue(raw string) (int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, errors.New("empty port value")
	}

	port, err := strconv.Atoi(trimmed)
	if err != nil {
		return 0, fmt.Errorf("invalid port value: %s", trimmed)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port out of range: %d", port)
	}
	return port, nil
}
