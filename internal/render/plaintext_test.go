package render

import (
	"testing"
	"time"

	"vibescan/internal/domain"
)

func TestRenderPlainEmptySnapshot(t *testing.T) {
	result := domain.ScanResult{}

	got := RenderPlain(result)
	expected := "" +
		"Scan Results\n" +
		"Tool: (unknown)\n" +
		"Generated: (unknown)\n" +
		"Targets: 0\n" +
		"No targets.\n"

	if got != expected {
		t.Fatalf("unexpected output:\n%s", got)
	}
}

func TestRenderPlainPopulatedSnapshot(t *testing.T) {
	result := domain.ScanResult{
		Tool:        "vibescan",
		GeneratedAt: time.Date(2026, time.February, 3, 10, 30, 0, 0, time.UTC),
		Targets: []domain.Target{
			{
				ID:       "target-1",
				Address:  "192.0.2.1",
				Hostname: "example.local",
				Ports: []domain.Port{{
					Number:   443,
					Protocol: "tcp",
					State:    "open",
				}},
				Services: []domain.Service{{
					Name:    "https",
					Product: "nginx",
					Version: "1.24",
					Port:    443,
					CVEs: []domain.CVE{{
						ID:          "CVE-2099-0002",
						Severity:    "medium",
						Description: "Example service vulnerability.",
					}},
				}},
				CVEs: []domain.CVE{{
					ID:          "CVE-2099-0001",
					Severity:    "high",
					Description: "Example vulnerability.",
				}},
				WebTechnologies: []domain.WebTechnology{{
					Name:     "nginx",
					Version:  "1.24",
					Category: "server",
				}},
			},
		},
	}

	got := RenderPlain(result)
	expected := "" +
		"Scan Results\n" +
		"Tool: vibescan\n" +
		"Generated: 2026-02-03T10:30:00Z\n" +
		"Targets: 1\n" +
		"Target 1: 192.0.2.1 (example.local)\n" +
		"ID: target-1\n" +
		"Ports (1)\n" +
		"  - 443/tcp open\n" +
		"Services (1)\n" +
		"  - https (nginx 1.24) on 443\n" +
		"CVEs (2)\n" +
		"  - CVE-2099-0001 [high] Example vulnerability.\n" +
		"  - https:443 -> CVE-2099-0002 [medium] Example service vulnerability.\n" +
		"Web Technologies (1)\n" +
		"  - nginx 1.24 (server)\n"

	if got != expected {
		t.Fatalf("unexpected output:\n%s", got)
	}
}
