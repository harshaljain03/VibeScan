package render

import (
	"encoding/xml"
	"time"

	"vibescan/internal/domain"
)

// RenderXML returns an XML representation of a scan result.
func RenderXML(result domain.ScanResult) (string, error) {
	payload, err := xml.MarshalIndent(toXMLResult(result), "", "  ")
	if err != nil {
		return "", err
	}
	return xml.Header + string(payload) + "\n", nil
}

type xmlScanResult struct {
	XMLName     xml.Name    `xml:"vibescan"`
	Tool        string      `xml:"tool,attr,omitempty"`
	GeneratedAt string      `xml:"generated_at,attr,omitempty"`
	Targets     []xmlTarget `xml:"targets>target"`
}

type xmlTarget struct {
	ID              string             `xml:"id,attr,omitempty"`
	Address         string             `xml:"address,attr,omitempty"`
	Hostname        string             `xml:"hostname,attr,omitempty"`
	Ports           []xmlPort          `xml:"ports>port"`
	Services        []xmlService       `xml:"services>service"`
	CVEs            []xmlCVE           `xml:"cves>cve"`
	WebTechnologies []xmlWebTechnology `xml:"web_technologies>technology"`
}

type xmlPort struct {
	Number   int    `xml:"number,attr,omitempty"`
	Protocol string `xml:"protocol,attr,omitempty"`
	State    string `xml:"state,attr,omitempty"`
}

type xmlService struct {
	Name    string   `xml:"name,attr,omitempty"`
	Product string   `xml:"product,attr,omitempty"`
	Version string   `xml:"version,attr,omitempty"`
	Port    int      `xml:"port,attr,omitempty"`
	CVEs    []xmlCVE `xml:"cves>cve"`
}

type xmlCVE struct {
	ID          string `xml:"id,attr,omitempty"`
	Severity    string `xml:"severity,attr,omitempty"`
	Description string `xml:"description,omitempty"`
}

type xmlWebTechnology struct {
	Name     string   `xml:"name,attr,omitempty"`
	Version  string   `xml:"version,attr,omitempty"`
	Category string   `xml:"category,attr,omitempty"`
	CVEs     []xmlCVE `xml:"cves>cve"`
}

func toXMLResult(result domain.ScanResult) xmlScanResult {
	xmlResult := xmlScanResult{
		Tool:        result.Tool,
		GeneratedAt: formatTime(result.GeneratedAt),
		Targets:     make([]xmlTarget, 0, len(result.Targets)),
	}

	for _, target := range result.Targets {
		xmlTarget := xmlTarget{
			ID:              target.ID,
			Address:         target.Address,
			Hostname:        target.Hostname,
			Ports:           make([]xmlPort, 0, len(target.Ports)),
			Services:        make([]xmlService, 0, len(target.Services)),
			CVEs:            mapCVEs(target.CVEs),
			WebTechnologies: make([]xmlWebTechnology, 0, len(target.WebTechnologies)),
		}

		for _, port := range target.Ports {
			xmlTarget.Ports = append(xmlTarget.Ports, xmlPort{
				Number:   port.Number,
				Protocol: port.Protocol,
				State:    port.State,
			})
		}

		for _, service := range target.Services {
			xmlTarget.Services = append(xmlTarget.Services, xmlService{
				Name:    service.Name,
				Product: service.Product,
				Version: service.Version,
				Port:    service.Port,
				CVEs:    mapCVEs(service.CVEs),
			})
		}

		for _, tech := range target.WebTechnologies {
			xmlTarget.WebTechnologies = append(xmlTarget.WebTechnologies, xmlWebTechnology{
				Name:     tech.Name,
				Version:  tech.Version,
				Category: tech.Category,
				CVEs:     mapCVEs(tech.CVEs),
			})
		}

		xmlResult.Targets = append(xmlResult.Targets, xmlTarget)
	}

	return xmlResult
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

func mapCVEs(cves []domain.CVE) []xmlCVE {
	if len(cves) == 0 {
		return nil
	}

	mapped := make([]xmlCVE, 0, len(cves))
	for _, cve := range cves {
		mapped = append(mapped, xmlCVE{
			ID:          cve.ID,
			Severity:    cve.Severity,
			Description: cve.Description,
		})
	}
	return mapped
}
