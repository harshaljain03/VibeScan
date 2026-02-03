package render

import (
	"encoding/json"

	"vibescan/internal/domain"
)

// RenderJSON returns a JSON representation of a scan result.
func RenderJSON(result domain.ScanResult) (string, error) {
	payload, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(payload) + "\n", nil
}
