package scan

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"vibescan/internal/cve"
	"vibescan/internal/domain"
)

type fakeWebScannerBase struct {
	result domain.Target
}

func (f fakeWebScannerBase) Scan(_ context.Context, _ domain.Target) (domain.Target, error) {
	return f.result, nil
}

type fakeWebCVEClient struct {
	responses map[string][]domain.CVE
	errors    map[string]error
}

func (f fakeWebCVEClient) FindByService(_ context.Context, service domain.Service) ([]domain.CVE, error) {
	query, _ := cve.BuildQuery(service)
	if err := f.errors[query]; err != nil {
		return nil, err
	}
	return f.responses[query], nil
}

func TestWebScannerAttachesTechAndCVEs(t *testing.T) {
	base := fakeWebScannerBase{result: domain.Target{
		Address: "example.com",
		Ports:   []domain.Port{{Number: 80, Protocol: "tcp", State: "open"}},
	}}
	client := fakeWebCVEClient{
		responses: map[string][]domain.CVE{
			"WordPress 6.4.2": {{ID: "CVE-2099-0004"}},
		},
		errors: map[string]error{},
	}

	fetcher := func(_ context.Context, _ webEndpoint, _ time.Duration, _ int64, _ *http.Client) (webEvidence, error) {
		return webEvidence{body: "<meta name=\"generator\" content=\"WordPress 6.4.2\">"}, nil
	}

	scanner := NewWebScanner(base, client, WebOptions{Recursive: true, Timeout: time.Second})
	scanner.Fetcher = fetcher

	result, err := scanner.Scan(context.Background(), domain.Target{Address: "example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.WebTechnologies) != 1 {
		t.Fatalf("expected 1 technology, got %d", len(result.WebTechnologies))
	}

	tech := result.WebTechnologies[0]
	if tech.Name != "WordPress" || tech.Version != "6.4.2" {
		t.Fatalf("unexpected tech: %+v", tech)
	}
	if len(tech.CVEs) != 1 || tech.CVEs[0].ID != "CVE-2099-0004" {
		t.Fatalf("expected CVE attached, got %+v", tech.CVEs)
	}
}

func TestWebScannerGracefulFailure(t *testing.T) {
	base := fakeWebScannerBase{result: domain.Target{
		Address: "example.com",
		Ports:   []domain.Port{{Number: 80, Protocol: "tcp", State: "open"}},
	}}

	fetcher := func(_ context.Context, _ webEndpoint, _ time.Duration, _ int64, _ *http.Client) (webEvidence, error) {
		return webEvidence{}, errors.New("fetch failed")
	}

	scanner := NewWebScanner(base, nil, WebOptions{Recursive: true, Timeout: time.Second})
	scanner.Fetcher = fetcher

	result, err := scanner.Scan(context.Background(), domain.Target{Address: "example.com"})
	if err == nil {
		t.Fatal("expected error")
	}

	if len(result.WebTechnologies) != 0 {
		t.Fatalf("expected no technologies, got %d", len(result.WebTechnologies))
	}
}
