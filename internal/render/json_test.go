package render

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRenderJSONGolden(t *testing.T) {
	result := sampleScanResult()
	got, err := RenderJSON(result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	path := filepath.Join("testdata", "scan.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read golden file: %v", err)
	}

	expected := string(payload)
	if got != expected {
		t.Fatalf("unexpected JSON output:\n%s", got)
	}
}
