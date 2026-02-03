package cmd

import (
	"bytes"
	"strings"
	"testing"

	"vibescan/internal/scan"
)

func TestRootCommandExecutes(t *testing.T) {
	root := NewRootCmdWithOptions(rootOptions{
		scannerFactory: func(_ scanOptions) scan.Scanner {
			return scan.NoOpScanner{}
		},
	})
	root.SetArgs([]string{"example.com"})

	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)

	if err := root.Execute(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestRootCommandOutputContainsNameAndDescription(t *testing.T) {
	root := NewRootCmdWithOptions(rootOptions{
		scannerFactory: func(_ scanOptions) scan.Scanner {
			return scan.NoOpScanner{}
		},
	})
	root.SetArgs([]string{"example.com"})

	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)

	if err := root.Execute(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	output := out.String()
	if !strings.Contains(output, toolName) {
		t.Fatalf("expected output to contain tool name %q", toolName)
	}

	if !strings.Contains(output, oneLineDesc) {
		t.Fatalf("expected output to contain description %q", oneLineDesc)
	}
}
