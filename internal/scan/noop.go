package scan

import (
	"context"

	"vibescan/internal/domain"
)

// NoOpScanner returns the target unchanged.
type NoOpScanner struct{}

// Scan satisfies the Scanner interface.
func (NoOpScanner) Scan(_ context.Context, target domain.Target) (domain.Target, error) {
	return target, nil
}
