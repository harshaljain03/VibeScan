package input

import (
	"strings"
	"testing"
	"time"
)

func TestParseNmapXML(t *testing.T) {
	payload := `<?xml version="1.0"?>
<nmaprun scanner="nmap" start="1700000000">
  <host>
    <status state="up" />
    <address addr="192.0.2.1" addrtype="ipv4" />
    <hostnames>
      <hostname name="example.local" />
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" />
        <service name="http" product="nginx" version="1.25.3" />
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed" />
      </port>
    </ports>
  </host>
</nmaprun>`

	result, err := ParseNmapXML([]byte(payload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Tool != "nmap" {
		t.Fatalf("expected tool nmap, got %q", result.Tool)
	}

	expectedTime := time.Unix(1700000000, 0).UTC()
	if !result.GeneratedAt.Equal(expectedTime) {
		t.Fatalf("expected generated time %s, got %s", expectedTime, result.GeneratedAt)
	}

	if len(result.Targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(result.Targets))
	}

	target := result.Targets[0]
	if target.Address != "192.0.2.1" {
		t.Fatalf("expected address 192.0.2.1, got %q", target.Address)
	}
	if target.Hostname != "example.local" {
		t.Fatalf("expected hostname example.local, got %q", target.Hostname)
	}

	if len(target.Ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(target.Ports))
	}

	if !strings.EqualFold(target.Ports[0].State, "open") {
		t.Fatalf("expected port 80 open, got %q", target.Ports[0].State)
	}
	if !strings.EqualFold(target.Ports[1].State, "closed") {
		t.Fatalf("expected port 22 closed, got %q", target.Ports[1].State)
	}

	if len(target.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(target.Services))
	}

	service := target.Services[0]
	if service.Name != "http" || service.Product != "nginx" || service.Version != "1.25.3" {
		t.Fatalf("unexpected service: %+v", service)
	}
}
