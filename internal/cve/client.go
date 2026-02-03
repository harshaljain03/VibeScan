package cve

import (
	"context"

	"vibescan/internal/domain"
)

// Client looks up CVEs for a given service.
type Client interface {
	FindByService(ctx context.Context, service domain.Service) ([]domain.CVE, error)
}
