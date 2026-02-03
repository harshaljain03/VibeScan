package scan

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"vibescan/internal/cve"
	"vibescan/internal/domain"
)

type fakeScanner struct {
	result domain.Target
}

func (f fakeScanner) Scan(_ context.Context, _ domain.Target) (domain.Target, error) {
	return f.result, nil
}

type fakeCVEClient struct {
	responses map[string][]domain.CVE
	errors    map[string]error
}

func (f fakeCVEClient) FindByService(_ context.Context, service domain.Service) ([]domain.CVE, error) {
	key, _ := cve.BuildQuery(service)
	if err := f.errors[key]; err != nil {
		return nil, err
	}
	return f.responses[key], nil
}

func TestCVEEnricherAttachesCVEs(t *testing.T) {
	services := []domain.Service{
		{Name: "http", Product: "nginx", Version: "1.25.3", Port: 80},
		{Name: "ssh", Product: "OpenSSH", Version: "9.3", Port: 22},
	}
	scanner := fakeScanner{result: domain.Target{Address: "example.com", Services: services}}
	client := fakeCVEClient{
		responses: map[string][]domain.CVE{
			"nginx 1.25.3": {{ID: "CVE-2099-0001", Severity: "high"}},
		},
		errors: map[string]error{
			"OpenSSH 9.3": errors.New("nvd error"),
		},
	}

	enricher := NewCVEEnricher(scanner, client)
	result, err := enricher.Scan(context.Background(), domain.Target{Address: "example.com"})
	if err == nil {
		t.Fatal("expected error from CVE client")
	}

	if len(result.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(result.Services))
	}

	if len(result.Services[0].CVEs) != 1 || result.Services[0].CVEs[0].ID != "CVE-2099-0001" {
		t.Fatalf("expected CVE attached to nginx service, got %+v", result.Services[0].CVEs)
	}

	if len(result.Services[1].CVEs) != 0 {
		t.Fatalf("expected no CVEs on ssh service, got %+v", result.Services[1].CVEs)
	}

	if !reflect.DeepEqual(result.Services[0].CVEs, []domain.CVE{{ID: "CVE-2099-0001", Severity: "high"}}) {
		t.Fatalf("unexpected CVEs: %+v", result.Services[0].CVEs)
	}
}
