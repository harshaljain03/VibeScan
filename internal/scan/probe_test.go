package scan

import "testing"

func TestParseProductVersion(t *testing.T) {
	cases := []struct {
		input   string
		product string
		version string
	}{
		{"nginx/1.25.3", "nginx", "1.25.3"},
		{"OpenSSH_9.3", "OpenSSH", "9.3"},
		{"Apache/2.4.58 (Unix)", "Apache", "2.4.58"},
		{"Microsoft-IIS/10.0", "Microsoft-IIS", "10.0"},
		{"Drupal 10", "Drupal", "10"},
		{"no-version", "", ""},
	}

	for _, tc := range cases {
		product, version := parseProductVersion(tc.input)
		if product != tc.product || version != tc.version {
			t.Fatalf("input %q expected %q/%q got %q/%q", tc.input, tc.product, tc.version, product, version)
		}
	}
}
