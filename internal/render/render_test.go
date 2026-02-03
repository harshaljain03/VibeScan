package render

import (
	"time"

	"vibescan/internal/domain"
)

func sampleScanResult() domain.ScanResult {
	return domain.ScanResult{
		Tool:        "vibescan",
		GeneratedAt: time.Date(2026, time.February, 3, 10, 30, 0, 0, time.UTC),
		Targets: []domain.Target{
			{
				ID:       "target-1",
				Address:  "192.0.2.1",
				Hostname: "example.local",
				Ports: []domain.Port{{
					Number:   80,
					Protocol: "tcp",
					State:    "open",
				}},
				Services: []domain.Service{{
					Name:    "http",
					Product: "nginx",
					Version: "1.25.3",
					Port:    80,
					CVEs: []domain.CVE{{
						ID:          "CVE-2099-0005",
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
					Name:     "WordPress",
					Version:  "6.4.2",
					Category: "cms",
					CVEs: []domain.CVE{{
						ID:          "CVE-2099-0006",
						Severity:    "low",
						Description: "Example web tech vulnerability.",
					}},
				}},
			},
		},
	}
}
