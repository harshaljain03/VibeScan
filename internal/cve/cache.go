package cve

import (
	"context"
	"sync"

	"vibescan/internal/domain"
)

// CachedClient wraps a CVE client with an in-memory cache.
type CachedClient struct {
	Base  Client
	mu    sync.RWMutex
	cache map[string][]domain.CVE
}

// NewCachedClient wraps the provided client in a cache.
func NewCachedClient(base Client) *CachedClient {
	return &CachedClient{Base: base, cache: make(map[string][]domain.CVE)}
}

// FindByService retrieves CVEs using a cached lookup.
func (c *CachedClient) FindByService(ctx context.Context, service domain.Service) ([]domain.CVE, error) {
	if c == nil || c.Base == nil {
		return nil, nil
	}

	key, ok := BuildQuery(service)
	if !ok {
		return nil, nil
	}

	c.mu.RLock()
	cached, ok := c.cache[key]
	c.mu.RUnlock()
	if ok {
		return cloneCVEs(cached), nil
	}

	cves, err := c.Base.FindByService(ctx, service)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.cache[key] = cloneCVEs(cves)
	c.mu.Unlock()

	return cloneCVEs(cves), nil
}

func cloneCVEs(cves []domain.CVE) []domain.CVE {
	if len(cves) == 0 {
		return nil
	}

	clone := make([]domain.CVE, len(cves))
	copy(clone, cves)
	return clone
}
