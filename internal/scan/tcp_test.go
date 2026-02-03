package scan

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"vibescan/internal/domain"
)

type fakeConn struct{}

func (fakeConn) Read(_ []byte) (int, error)         { return 0, nil }
func (fakeConn) Write(_ []byte) (int, error)        { return 0, nil }
func (fakeConn) Close() error                       { return nil }
func (fakeConn) LocalAddr() net.Addr                { return fakeAddr("local") }
func (fakeConn) RemoteAddr() net.Addr               { return fakeAddr("remote") }
func (fakeConn) SetDeadline(_ time.Time) error      { return nil }
func (fakeConn) SetReadDeadline(_ time.Time) error  { return nil }
func (fakeConn) SetWriteDeadline(_ time.Time) error { return nil }

type fakeAddr string

func (a fakeAddr) Network() string { return string(a) }
func (a fakeAddr) String() string  { return string(a) }

func TestTCPScannerOpenClosedPorts(t *testing.T) {
	dialer := DialFunc(func(_ context.Context, _ string, address string) (net.Conn, error) {
		switch address {
		case "example.com:80":
			return fakeConn{}, nil
		case "example.com:81":
			return nil, errors.New("connection refused")
		default:
			return nil, errors.New("unexpected")
		}
	})

	scanner := NewTCPScanner([]int{80, 81}, 250*time.Millisecond, dialer)
	target := domain.Target{Address: "example.com"}

	result, err := scanner.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(result.Ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(result.Ports))
	}

	if result.Ports[0].Number != 80 || result.Ports[0].State != "open" {
		t.Fatalf("expected port 80 open, got %+v", result.Ports[0])
	}

	if result.Ports[1].Number != 81 || result.Ports[1].State != "closed" {
		t.Fatalf("expected port 81 closed, got %+v", result.Ports[1])
	}
}

func TestTCPScannerHTTPServiceDetection(t *testing.T) {
	port, stop := startTestServer(t, func(conn net.Conn) {
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
		response := "" +
			"HTTP/1.1 200 OK\r\n" +
			"Server: nginx/1.25.3\r\n" +
			"Content-Length: 0\r\n" +
			"\r\n"
		_, _ = conn.Write([]byte(response))
	})
	defer stop()

	scanner := NewTCPScanner([]int{port}, 500*time.Millisecond, nil)
	target := domain.Target{Address: "127.0.0.1"}

	result, err := scanner.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(result.Ports) != 1 || result.Ports[0].State != "open" {
		t.Fatalf("expected port open, got %+v", result.Ports)
	}

	if len(result.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(result.Services))
	}

	service := result.Services[0]
	if service.Name != "http" {
		t.Fatalf("expected http service, got %+v", service)
	}
	if service.Product != "nginx" || service.Version != "1.25.3" {
		t.Fatalf("expected nginx/1.25.3, got %+v", service)
	}
	if service.Port != port {
		t.Fatalf("expected service port %d, got %d", port, service.Port)
	}
}

func TestTCPScannerBannerDetection(t *testing.T) {
	port, stop := startTestServer(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.3\r\n"))
	})
	defer stop()

	scanner := NewTCPScanner([]int{port}, 500*time.Millisecond, nil)
	target := domain.Target{Address: "127.0.0.1"}

	result, err := scanner.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(result.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(result.Services))
	}

	service := result.Services[0]
	if service.Name != "ssh" {
		t.Fatalf("expected ssh service, got %+v", service)
	}
	if service.Product != "OpenSSH" || service.Version != "9.3" {
		t.Fatalf("expected OpenSSH 9.3, got %+v", service)
	}
	if service.Port != port {
		t.Fatalf("expected service port %d, got %d", port, service.Port)
	}
}

func startTestServer(t *testing.T, handler func(net.Conn)) (int, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	tcpListener := listener.(*net.TCPListener)
	_ = tcpListener.SetDeadline(time.Now().Add(2 * time.Second))

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		handler(conn)
		_ = conn.Close()
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	stop := func() {
		_ = listener.Close()
	}
	return port, stop
}
