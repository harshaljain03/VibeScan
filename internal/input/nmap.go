package input

import (
	"encoding/xml"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"vibescan/internal/domain"
)

// ParseNmapFile parses an Nmap XML file into a ScanResult.
func ParseNmapFile(path string) (domain.ScanResult, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return domain.ScanResult{}, err
	}
	return ParseNmapXML(payload)
}

// ParseNmapXML parses Nmap XML data into a ScanResult.
func ParseNmapXML(data []byte) (domain.ScanResult, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return domain.ScanResult{}, err
	}

	result := domain.ScanResult{Targets: make([]domain.Target, 0, len(run.Hosts))}
	result.Tool = strings.TrimSpace(run.Scanner)
	if start, err := strconv.ParseInt(strings.TrimSpace(run.Start), 10, 64); err == nil {
		result.GeneratedAt = time.Unix(start, 0).UTC()
	}

	for _, host := range run.Hosts {
		if host.Status.State != "" && strings.ToLower(host.Status.State) != "up" {
			continue
		}

		address, hostname := extractAddress(host)
		if address == "" {
			continue
		}

		target := domain.Target{
			Address:  address,
			Hostname: hostname,
			Ports:    make([]domain.Port, 0, len(host.Ports.Ports)),
			Services: make([]domain.Service, 0, len(host.Ports.Ports)),
		}

		for _, port := range host.Ports.Ports {
			portState := strings.TrimSpace(port.State.State)
			target.Ports = append(target.Ports, domain.Port{
				Number:   port.PortID,
				Protocol: port.Protocol,
				State:    portState,
			})

			service := toService(port)
			if service != nil {
				target.Services = append(target.Services, *service)
			}
		}

		result.Targets = append(result.Targets, target)
	}

	return result, nil
}

func extractAddress(host nmapHost) (string, string) {
	address := ""
	for _, addr := range host.Addresses {
		addrValue := strings.TrimSpace(addr.Address)
		if addrValue == "" {
			continue
		}
		if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
			return addrValue, host.hostname()
		}
		if address == "" {
			address = addrValue
		}
	}

	if address == "" {
		return "", ""
	}
	return address, host.hostname()
}

func toService(port nmapPort) *domain.Service {
	name := strings.TrimSpace(port.Service.Name)
	product := strings.TrimSpace(port.Service.Product)
	version := strings.TrimSpace(port.Service.Version)
	if name == "" && product == "" && version == "" {
		return nil
	}

	return &domain.Service{
		Name:    name,
		Product: product,
		Version: version,
		Port:    port.PortID,
	}
}

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Scanner string     `xml:"scanner,attr"`
	Start   string     `xml:"start,attr"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status    nmapStatus     `xml:"status"`
	Addresses []nmapAddress  `xml:"address"`
	Hostnames nmapHostnames  `xml:"hostnames"`
	Ports     nmapPortBundle `xml:"ports"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Address  string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapHostnames struct {
	Hostnames []nmapHostname `xml:"hostname"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
}

type nmapPortBundle struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string        `xml:"protocol,attr"`
	PortID   int           `xml:"portid,attr"`
	State    nmapPortState `xml:"state"`
	Service  nmapService   `xml:"service"`
}

type nmapPortState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

func (h nmapHost) hostname() string {
	for _, host := range h.Hostnames.Hostnames {
		name := strings.TrimSpace(host.Name)
		if name != "" {
			return name
		}
	}
	return ""
}

func (p nmapPort) String() string {
	return fmt.Sprintf("%s/%d", p.Protocol, p.PortID)
}
