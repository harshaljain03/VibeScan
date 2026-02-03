package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectWebTechnologiesFromFixtures(t *testing.T) {
	cases := []struct {
		name     string
		file     string
		expected string
		version  string
	}{
		{"wordpress", "wordpress.html", "WordPress", "6.4.2"},
		{"drupal", "drupal.html", "Drupal", "10"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join("testdata", tc.file)
			payload, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed to read fixture: %v", err)
			}

			evidence := webEvidence{body: string(payload)}
			techs := detectWebTechnologies(evidence)

			found := false
			for _, tech := range techs {
				if tech.Name == tc.expected && tech.Version == tc.version {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected to find %s %s in %v", tc.expected, tc.version, techs)
			}
		})
	}
}

func TestDetectWebTechnologiesFromHeadersAndCookies(t *testing.T) {
	evidence := webEvidence{
		headers: map[string]string{
			"Server":       "nginx/1.25.3",
			"X-Powered-By": "PHP/8.2.1",
		},
		cookies: []string{"wordpress_logged_in", "sessionid"},
	}

	techs := detectWebTechnologies(evidence)
	assertTech := func(name, version string) {
		for _, tech := range techs {
			if tech.Name == name && tech.Version == version {
				return
			}
		}
		t.Fatalf("expected %s %s in %v", name, version, techs)
	}

	assertTech("nginx", "1.25.3")
	assertTech("PHP", "8.2.1")
	assertTech("WordPress", "")
}
