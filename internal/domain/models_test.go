package domain

import (
	"encoding/json"
	"testing"
)

func TestZeroValueMarshaling(t *testing.T) {
	cases := []struct {
		name  string
		value any
	}{
		{"Target", Target{}},
		{"Port", Port{}},
		{"Service", Service{}},
		{"CVE", CVE{}},
		{"WebTechnology", WebTechnology{}},
		{"ScanResult", ScanResult{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := json.Marshal(tc.value); err != nil {
				t.Fatalf("expected zero value to marshal, got error: %v", err)
			}
		})
	}
}

func TestJSONMarshaling(t *testing.T) {
	result := ScanResult{
		Tool: "vibescan",
		Targets: []Target{
			{
				ID:       "target-1",
				Address:  "192.0.2.1",
				Hostname: "example.local",
				Ports: []Port{{
					Number:   443,
					Protocol: "tcp",
					State:    "open",
				}},
				Services: []Service{{
					Name:    "https",
					Product: "nginx",
					Version: "1.24",
					Port:    443,
					CVEs: []CVE{{
						ID:          "CVE-2099-0002",
						Severity:    "medium",
						Description: "Example service vulnerability.",
					}},
				}},
				CVEs: []CVE{{
					ID:          "CVE-2099-0001",
					Severity:    "high",
					Description: "Example vulnerability.",
				}},
				WebTechnologies: []WebTechnology{{
					Name:     "nginx",
					Version:  "1.24",
					Category: "server",
					CVEs: []CVE{{
						ID:          "CVE-2099-0003",
						Severity:    "low",
						Description: "Example web technology issue.",
					}},
				}},
			},
		},
	}

	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("expected marshaling to succeed, got error: %v", err)
	}

	if len(payload) == 0 {
		t.Fatal("expected marshaled payload to be non-empty")
	}
}
