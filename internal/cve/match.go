package cve

import (
	"fmt"
	"strings"

	"vibescan/internal/domain"
)

// BuildQuery constructs a keyword query using service name/product and version.
func BuildQuery(service domain.Service) (string, bool) {
	product := strings.TrimSpace(service.Product)
	if product == "" {
		product = strings.TrimSpace(service.Name)
	}
	version := strings.TrimSpace(service.Version)
	if product == "" || version == "" {
		return "", false
	}
	return fmt.Sprintf("%s %s", product, version), true
}
