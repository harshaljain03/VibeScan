package scan

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"vibescan/internal/domain"
)

const (
	defaultProbeTimeout = 500 * time.Millisecond
	maxProbeBytes       = 4096
)

var (
	versionPattern = regexp.MustCompile(`(?i)([a-z][a-z0-9+_.-]*)[/_ ]v?(\d+(?:\.\d+)*)`) // product/version
	httpPorts      = map[int]struct{}{80: {}, 443: {}, 8000: {}, 8008: {}, 8080: {}, 8888: {}}
)

func detectService(conn net.Conn, host string, port int, timeout time.Duration) *domain.Service {
	banner := readBanner(conn, timeout)
	if banner != "" {
		if service := serviceFromBanner(banner, port); service != nil {
			return service
		}
	}

	if isHTTPPort(port) {
		return probeHTTP(conn, host, port, timeout)
	}

	return nil
}

func readBanner(conn net.Conn, timeout time.Duration) string {
	payload := readWithDeadline(conn, timeout, maxProbeBytes)
	if len(payload) == 0 {
		return ""
	}
	return strings.TrimSpace(string(payload))
}

func probeHTTP(conn net.Conn, host string, port int, timeout time.Duration) *domain.Service {
	deadline := effectiveTimeout(timeout)
	_ = conn.SetWriteDeadline(time.Now().Add(deadline))

	req := fmt.Sprintf("HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: vibescan\r\nConnection: close\r\n\r\n", host)
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil
	}

	payload := readWithDeadline(conn, timeout, maxProbeBytes)
	if len(payload) == 0 {
		return nil
	}

	resp := string(payload)
	if !strings.HasPrefix(resp, "HTTP/") {
		return nil
	}

	serverHeader := parseServerHeader(resp)
	product, version := parseProductVersion(serverHeader)

	service := &domain.Service{
		Name: "http",
		Port: port,
	}
	if product != "" {
		service.Product = product
	}
	if version != "" {
		service.Version = version
	}
	return service
}

func parseServerHeader(response string) string {
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			return ""
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "server:") {
			return strings.TrimSpace(line[len("server:"):])
		}
	}
	return ""
}

func serviceFromBanner(banner string, port int) *domain.Service {
	name := ""
	lower := strings.ToLower(banner)
	if strings.HasPrefix(banner, "SSH-") {
		name = "ssh"
	} else if strings.Contains(lower, "smtp") {
		name = "smtp"
	} else if strings.Contains(lower, "ftp") {
		name = "ftp"
	}

	product, version := parseProductVersion(banner)
	if name == "" && product == "" {
		return nil
	}

	service := &domain.Service{Port: port}
	if name != "" {
		service.Name = name
	} else {
		service.Name = strings.ToLower(product)
	}
	service.Product = product
	service.Version = version
	return service
}

func parseProductVersion(input string) (string, string) {
	match := versionPattern.FindStringSubmatch(input)
	if len(match) < 3 {
		return "", ""
	}

	product := strings.TrimSpace(match[1])
	version := strings.TrimSpace(match[2])
	return product, version
}

func readWithDeadline(conn net.Conn, timeout time.Duration, maxBytes int) []byte {
	deadline := effectiveTimeout(timeout)
	_ = conn.SetReadDeadline(time.Now().Add(deadline))
	buf := make([]byte, maxBytes)
	n, err := conn.Read(buf)
	if n <= 0 {
		return nil
	}
	_ = err
	return buf[:n]
}

func isHTTPPort(port int) bool {
	_, ok := httpPorts[port]
	return ok
}

func effectiveTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return defaultProbeTimeout
	}
	return timeout
}
