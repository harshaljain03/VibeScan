package render

import (
	"fmt"
	"strings"

	"vibescan/internal/domain"
)

// RenderPlain returns a plain-text representation of a scan result.
// It does not mutate the provided result.
func RenderPlain(result domain.ScanResult) string {
	var b strings.Builder

	b.WriteString("Scan Results\n")

	tool := result.Tool
	if tool == "" {
		tool = "(unknown)"
	}
	fmt.Fprintf(&b, "Tool: %s\n", tool)

	if result.GeneratedAt.IsZero() {
		b.WriteString("Generated: (unknown)\n")
	} else {
		fmt.Fprintf(&b, "Generated: %s\n", result.GeneratedAt.Format("2006-01-02T15:04:05Z07:00"))
	}

	fmt.Fprintf(&b, "Targets: %d\n", len(result.Targets))
	if len(result.Targets) == 0 {
		b.WriteString("No targets.\n")
		return b.String()
	}

	for i, target := range result.Targets {
		if i > 0 {
			b.WriteString("\n")
		}

		address := target.Address
		if address == "" {
			address = "(unknown)"
		}

		header := fmt.Sprintf("Target %d: %s", i+1, address)
		if target.Hostname != "" {
			header = fmt.Sprintf("%s (%s)", header, target.Hostname)
		}
		b.WriteString(header + "\n")

		if target.ID != "" {
			fmt.Fprintf(&b, "ID: %s\n", target.ID)
		}

		writeSection(&b, "Ports", formatPorts(target.Ports))
		writeSection(&b, "Services", formatServices(target.Services))
		writeSection(&b, "CVEs", formatTargetCVEs(target))
		writeSection(&b, "Web Technologies", formatWebTechs(target.WebTechnologies))
	}

	return b.String()
}

func writeSection(b *strings.Builder, title string, lines []string) {
	fmt.Fprintf(b, "%s (%d)\n", title, len(lines))
	if len(lines) == 0 {
		b.WriteString("  (none)\n")
		return
	}

	for _, line := range lines {
		fmt.Fprintf(b, "  - %s\n", line)
	}
}

func formatPorts(ports []domain.Port) []string {
	lines := make([]string, 0, len(ports))
	for _, port := range ports {
		proto := port.Protocol
		if proto == "" {
			proto = "?"
		}

		state := port.State
		line := strings.TrimSpace(fmt.Sprintf("%d/%s %s", port.Number, proto, state))
		lines = append(lines, line)
	}
	return lines
}

func formatServices(services []domain.Service) []string {
	lines := make([]string, 0, len(services))
	for _, service := range services {
		name := service.Name
		if name == "" {
			name = "(unknown)"
		}

		detail := strings.TrimSpace(fmt.Sprintf("%s %s", service.Product, service.Version))
		line := name
		if detail != "" {
			line = fmt.Sprintf("%s (%s)", line, detail)
		}
		if service.Port > 0 {
			line = fmt.Sprintf("%s on %d", line, service.Port)
		}

		lines = append(lines, line)
	}
	return lines
}

func formatTargetCVEs(target domain.Target) []string {
	lines := make([]string, 0, len(target.CVEs))
	for _, cve := range target.CVEs {
		lines = append(lines, formatCVELine(cve))
	}

	for _, service := range target.Services {
		if len(service.CVEs) == 0 {
			continue
		}

		label := serviceLabel(service)
		for _, cve := range service.CVEs {
			line := formatCVELine(cve)
			if label != "" {
				line = fmt.Sprintf("%s -> %s", label, line)
			}
			lines = append(lines, line)
		}
	}

	for _, tech := range target.WebTechnologies {
		if len(tech.CVEs) == 0 {
			continue
		}

		label := webTechLabel(tech)
		for _, cve := range tech.CVEs {
			line := formatCVELine(cve)
			if label != "" {
				line = fmt.Sprintf("%s -> %s", label, line)
			}
			lines = append(lines, line)
		}
	}

	return lines
}

func formatCVELine(cve domain.CVE) string {
	id := cve.ID
	if id == "" {
		id = "(unknown id)"
	}

	parts := []string{id}
	if cve.Severity != "" {
		parts = append(parts, fmt.Sprintf("[%s]", cve.Severity))
	}
	if cve.Description != "" {
		parts = append(parts, cve.Description)
	}
	return strings.Join(parts, " ")
}

func serviceLabel(service domain.Service) string {
	label := strings.TrimSpace(service.Name)
	if label == "" {
		label = strings.TrimSpace(service.Product)
	}
	if label == "" {
		return ""
	}
	if service.Port > 0 {
		label = fmt.Sprintf("%s:%d", label, service.Port)
	}
	return label
}

func webTechLabel(tech domain.WebTechnology) string {
	label := strings.TrimSpace(tech.Name)
	if label == "" {
		return ""
	}
	if tech.Version != "" {
		label = fmt.Sprintf("%s %s", label, tech.Version)
	}
	return label
}

func formatWebTechs(techs []domain.WebTechnology) []string {
	lines := make([]string, 0, len(techs))
	for _, tech := range techs {
		name := tech.Name
		if name == "" {
			name = "(unknown)"
		}

		line := name
		if tech.Version != "" {
			line = fmt.Sprintf("%s %s", line, tech.Version)
		}
		if tech.Category != "" {
			line = fmt.Sprintf("%s (%s)", line, tech.Category)
		}
		lines = append(lines, line)
	}
	return lines
}
