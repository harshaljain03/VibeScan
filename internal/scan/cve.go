package scan

import (
	"context"
	"errors"

	"vibescan/internal/cve"
	"vibescan/internal/domain"
)

// CVEEnricher attaches CVEs to detected services.
type CVEEnricher struct {
	Scanner Scanner
	Client  cve.Client
}

// NewCVEEnricher wraps a scanner with CVE enrichment.
func NewCVEEnricher(scanner Scanner, client cve.Client) *CVEEnricher {
	return &CVEEnricher{Scanner: scanner, Client: client}
}

// Scan performs the underlying scan and enriches services with CVEs.
func (e *CVEEnricher) Scan(ctx context.Context, target domain.Target) (domain.Target, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if e == nil || e.Scanner == nil {
		return target, nil
	}

	scanned, err := e.Scanner.Scan(ctx, target)
	if err != nil {
		return scanned, err
	}
	if e.Client == nil || len(scanned.Services) == 0 {
		return scanned, nil
	}

	var errs error
	services := make([]domain.Service, len(scanned.Services))
	copy(services, scanned.Services)

	for i, service := range services {
		if ctx.Err() != nil {
			return scanned, ctx.Err()
		}

		cves, err := e.Client.FindByService(ctx, service)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		service.CVEs = cves
		services[i] = service
	}

	scanned.Services = services
	return scanned, errs
}
