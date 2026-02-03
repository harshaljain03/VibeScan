package input

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseTargets(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "targets.txt")
	fileContents := "" +
		"\n" +
		"# comment\n" +
		"// another comment\n" +
		"example.com\n" +
		"https://example.com/\n" +
		"192.0.2.1\n" +
		"example.com\n"
	if err := os.WriteFile(filePath, []byte(fileContents), 0o600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	cases := []struct {
		name     string
		input    string
		expected []string
		wantErr  bool
	}{
		{
			name:     "single ip",
			input:    "192.0.2.10",
			expected: []string{"192.0.2.10"},
		},
		{
			name:     "single domain",
			input:    "example.com",
			expected: []string{"example.com"},
		},
		{
			name:     "domain trailing slash",
			input:    "example.com/",
			expected: []string{"example.com"},
		},
		{
			name:     "url normalization",
			input:    "https://example.com/path/",
			expected: []string{"example.com/path"},
		},
		{
			name:  "comma list",
			input: "example.com, 192.0.2.1, https://foo.bar/ , ,example.com",
			expected: []string{
				"example.com",
				"192.0.2.1",
				"foo.bar",
			},
		},
		{
			name:  "file input",
			input: filePath,
			expected: []string{
				"example.com",
				"192.0.2.1",
			},
		},
		{
			name:    "empty input",
			input:   "   ",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseTargets(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !reflect.DeepEqual(got, tc.expected) {
				t.Fatalf("expected %v, got %v", tc.expected, got)
			}
		})
	}
}

func TestParseTargetsNoValidTargets(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "empty.txt")
	fileContents := "" +
		"\n" +
		"# comment only\n" +
		"// another comment\n"

	if err := os.WriteFile(filePath, []byte(fileContents), 0o600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	if _, err := ParseTargets(filePath); err == nil {
		t.Fatal("expected error for file with no valid targets")
	}
}
