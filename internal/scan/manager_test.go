package scan

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"vibescan/internal/domain"
)

type mockScanner struct {
	results map[string]domain.Target
	errors  map[string]error
	calls   []string
}

func (m *mockScanner) Scan(_ context.Context, target domain.Target) (domain.Target, error) {
	m.calls = append(m.calls, target.Address)
	result, ok := m.results[target.Address]
	if !ok {
		result = target
	}
	return result, m.errors[target.Address]
}

func TestScanManagerContinuesOnFailure(t *testing.T) {
	input := domain.ScanResult{
		Tool: "vibescan",
		Targets: []domain.Target{
			{Address: "alpha"},
			{Address: "beta"},
			{Address: "gamma"},
		},
	}

	mockErr := errors.New("scan failed")
	ms := &mockScanner{
		results: map[string]domain.Target{
			"alpha": {Address: "alpha", Hostname: "alpha.local"},
			"beta":  {Address: "beta", Ports: []domain.Port{{Number: 80, Protocol: "tcp", State: "open"}}},
			"gamma": {Address: "gamma", Services: []domain.Service{{Name: "ssh"}}},
		},
		errors: map[string]error{
			"beta": mockErr,
		},
	}

	manager := ScanManager{Scanner: ms}
	result, errs := manager.Run(context.Background(), input)

	if len(errs) != 1 || errs[0] != mockErr {
		t.Fatalf("expected one error %v, got %v", mockErr, errs)
	}

	expectedTargets := []domain.Target{
		{Address: "alpha", Hostname: "alpha.local"},
		{Address: "beta", Ports: []domain.Port{{Number: 80, Protocol: "tcp", State: "open"}}},
		{Address: "gamma", Services: []domain.Service{{Name: "ssh"}}},
	}

	if !reflect.DeepEqual(result.Targets, expectedTargets) {
		t.Fatalf("expected targets %v, got %v", expectedTargets, result.Targets)
	}
}

func TestScanManagerReturnsMissingScannerError(t *testing.T) {
	input := domain.ScanResult{Targets: []domain.Target{{Address: "alpha"}}}
	manager := ScanManager{}

	result, errs := manager.Run(context.Background(), input)

	if len(errs) != 1 || !errors.Is(errs[0], ErrScannerMissing) {
		t.Fatalf("expected ErrScannerMissing, got %v", errs)
	}

	if len(result.Targets) != 1 || result.Targets[0].Address != "alpha" {
		t.Fatalf("expected targets to be preserved, got %v", result.Targets)
	}
}
