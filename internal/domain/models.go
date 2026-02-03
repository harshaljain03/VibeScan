package domain

import "time"

// Target represents a scan target and its discovered surface.
type Target struct {
	ID              string          `json:"id"`
	Address         string          `json:"address"`
	Hostname        string          `json:"hostname"`
	Ports           []Port          `json:"ports"`
	Services        []Service       `json:"services"`
	CVEs            []CVE           `json:"cves"`
	WebTechnologies []WebTechnology `json:"web_technologies"`
}

// Port represents a network port on a target.
type Port struct {
	Number   int    `json:"number"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
}

// Service represents an identified service.
type Service struct {
	Name    string `json:"name"`
	Product string `json:"product"`
	Version string `json:"version"`
	Port    int    `json:"port"`
	CVEs    []CVE  `json:"cves"`
}

// CVE represents a vulnerability reference.
type CVE struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// WebTechnology represents an identified web technology.
type WebTechnology struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Category string `json:"category"`
	CVEs     []CVE  `json:"cves"`
}

// ScanResult aggregates scan data across targets.
type ScanResult struct {
	Tool        string    `json:"tool"`
	GeneratedAt time.Time `json:"generated_at"`
	Targets     []Target  `json:"targets"`
}
