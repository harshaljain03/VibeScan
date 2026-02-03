package scan

import (
	"context"
	"fmt"
	"net"
	"time"

	"vibescan/internal/domain"
)

// Dialer abstracts the network dialer for testing.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// DialFunc adapts a function to the Dialer interface.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// DialContext implements the Dialer interface.
func (fn DialFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return fn(ctx, network, address)
}

// TCPScanner performs TCP connect scans.
type TCPScanner struct {
	Ports   []int
	Timeout time.Duration
	Dialer  Dialer
}

// NewTCPScanner builds a TCPScanner with the provided settings.
func NewTCPScanner(ports []int, timeout time.Duration, dialer Dialer) *TCPScanner {
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	return &TCPScanner{Ports: ports, Timeout: timeout, Dialer: dialer}
}

// Scan performs a TCP connect scan for a target.
func (s *TCPScanner) Scan(ctx context.Context, target domain.Target) (domain.Target, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil {
		return target, nil
	}

	scanned := target
	scanned.Ports = make([]domain.Port, 0, len(s.Ports))
	scanned.Services = make([]domain.Service, 0, len(s.Ports))

	for _, port := range s.Ports {
		portResult := domain.Port{
			Number:   port,
			Protocol: "tcp",
			State:    "closed",
		}

		conn, err := s.dial(ctx, target.Address, port)
		if err != nil {
			scanned.Ports = append(scanned.Ports, portResult)
			continue
		}

		portResult.State = "open"
		scanned.Ports = append(scanned.Ports, portResult)

		service := detectService(conn, target.Address, port, s.Timeout)
		_ = conn.Close()

		if service != nil {
			scanned.Services = append(scanned.Services, *service)
		}
	}

	return scanned, nil
}

func (s *TCPScanner) dial(ctx context.Context, address string, port int) (net.Conn, error) {
	target := fmt.Sprintf("%s:%d", address, port)
	if s.Timeout <= 0 {
		return s.Dialer.DialContext(ctx, "tcp", target)
	}

	dialCtx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	return s.Dialer.DialContext(dialCtx, "tcp", target)
}
