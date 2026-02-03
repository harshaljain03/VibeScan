package input

import (
	"reflect"
	"testing"
)

func TestParsePorts(t *testing.T) {
	cases := []struct {
		name     string
		spec     string
		expected []int
		wantErr  bool
	}{
		{
			name:     "single",
			spec:     "80",
			expected: []int{80},
		},
		{
			name:     "comma",
			spec:     "80,443",
			expected: []int{80, 443},
		},
		{
			name:     "range",
			spec:     "20-22",
			expected: []int{20, 21, 22},
		},
		{
			name:     "mixed",
			spec:     "80, 443, 8000-8002",
			expected: []int{80, 443, 8000, 8001, 8002},
		},
		{
			name:     "dedupe",
			spec:     "80,80,81-82,82",
			expected: []int{80, 81, 82},
		},
		{
			name:    "invalid",
			spec:    "0",
			wantErr: true,
		},
		{
			name:    "invalid range",
			spec:    "22-20",
			wantErr: true,
		},
		{
			name:    "empty",
			spec:    "  ",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePorts(tc.spec)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
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
