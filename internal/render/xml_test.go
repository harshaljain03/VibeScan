package render

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRenderXMLGolden(t *testing.T) {
	result := sampleScanResult()
	got, err := RenderXML(result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	path := filepath.Join("testdata", "scan.xml")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read golden file: %v", err)
	}

	expected := string(payload)
	if got != expected {
		t.Fatalf("unexpected XML output:\n%s", got)
	}
}
