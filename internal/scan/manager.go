package scan

import (
	"context"
	"errors"

	"vibescan/internal/domain"
)

// Scanner performs a scan for a single target.
type Scanner interface {
	Scan(ctx context.Context, target domain.Target) (domain.Target, error)
}

// ScanManager orchestrates scans across targets.
type ScanManager struct {
	Scanner Scanner
}

// ErrScannerMissing indicates the scan manager has no scanner configured.
var ErrScannerMissing = errors.New("scan manager requires a scanner")

// Run executes scans for each target, preserving partial results.
func (m ScanManager) Run(ctx context.Context, result domain.ScanResult) (domain.ScanResult, []error) {
	if ctx == nil {
		ctx = context.Background()
	}

	updated := domain.ScanResult{
		Tool:        result.Tool,
		GeneratedAt: result.GeneratedAt,
		Targets:     make([]domain.Target, 0, len(result.Targets)),
	}

	if m.Scanner == nil {
		for _, target := range result.Targets {
			updated.Targets = append(updated.Targets, target)
		}
		return updated, []error{ErrScannerMissing}
	}

	var errs []error
	for _, target := range result.Targets {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			return updated, errs
		}

		scannedTarget, err := m.Scanner.Scan(ctx, target)
		if err != nil {
			errs = append(errs, err)
		}

		updated.Targets = append(updated.Targets, scannedTarget)
	}

	return updated, errs
}
