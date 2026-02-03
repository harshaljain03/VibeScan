package cve

import (
	"testing"

	"vibescan/internal/domain"
)

func TestBuildQuery(t *testing.T) {
	cases := []struct {
		name    string
		service domain.Service
		query   string
		ok      bool
	}{
		{
			name:    "product and version",
			service: domain.Service{Product: "nginx", Version: "1.25.3"},
			query:   "nginx 1.25.3",
			ok:      true,
		},
		{
			name:    "fallback to name",
			service: domain.Service{Name: "OpenSSH", Version: "9.3"},
			query:   "OpenSSH 9.3",
			ok:      true,
		},
		{
			name:    "missing version",
			service: domain.Service{Name: "http"},
			ok:      false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			query, ok := BuildQuery(tc.service)
			if ok != tc.ok {
				t.Fatalf("expected ok=%v, got %v", tc.ok, ok)
			}
			if query != tc.query {
				t.Fatalf("expected query %q, got %q", tc.query, query)
			}
		})
	}
}
