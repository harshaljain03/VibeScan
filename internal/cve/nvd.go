package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"vibescan/internal/domain"
)

const defaultNVDBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// NVDClient queries the NVD CVE API.
type NVDClient struct {
	BaseURL        string
	APIKey         string
	HTTPClient     *http.Client
	ResultsPerPage int
}

// NewNVDClient constructs an NVD client with defaults.
func NewNVDClient(apiKey string, httpClient *http.Client) *NVDClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	return &NVDClient{
		BaseURL:        defaultNVDBaseURL,
		APIKey:         apiKey,
		HTTPClient:     httpClient,
		ResultsPerPage: 20,
	}
}

// FindByService queries NVD using the service name/product and version.
func (c *NVDClient) FindByService(ctx context.Context, service domain.Service) ([]domain.CVE, error) {
	if c == nil {
		return nil, nil
	}

	query, ok := BuildQuery(service)
	if !ok {
		return nil, nil
	}

	endpoint, err := c.buildURL(query)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "vibescan")
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}

	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("nvd api returned status %d", resp.StatusCode)
	}

	var payload nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	return extractCVEs(payload), nil
}

func (c *NVDClient) buildURL(query string) (string, error) {
	base := c.BaseURL
	if base == "" {
		base = defaultNVDBaseURL
	}

	parsed, err := url.Parse(base)
	if err != nil {
		return "", err
	}

	values := parsed.Query()
	values.Set("keywordSearch", query)
	if c.ResultsPerPage > 0 {
		values.Set("resultsPerPage", fmt.Sprintf("%d", c.ResultsPerPage))
	}
	parsed.RawQuery = values.Encode()

	return parsed.String(), nil
}

type nvdResponse struct {
	Vulnerabilities []nvdVulnerability `json:"vulnerabilities"`
}

type nvdVulnerability struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID           string           `json:"id"`
	Descriptions []nvdDescription `json:"descriptions"`
	Metrics      nvdMetrics       `json:"metrics"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CVSSMetricV31 []nvdMetric `json:"cvssMetricV31"`
	CVSSMetricV30 []nvdMetric `json:"cvssMetricV30"`
	CVSSMetricV2  []nvdMetric `json:"cvssMetricV2"`
}

type nvdMetric struct {
	CVSSData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	BaseSeverity string `json:"baseSeverity"`
}

func extractCVEs(payload nvdResponse) []domain.CVE {
	cves := make([]domain.CVE, 0, len(payload.Vulnerabilities))
	for _, vuln := range payload.Vulnerabilities {
		if strings.TrimSpace(vuln.CVE.ID) == "" {
			continue
		}

		cves = append(cves, domain.CVE{
			ID:          vuln.CVE.ID,
			Severity:    pickSeverity(vuln.CVE.Metrics),
			Description: pickDescription(vuln.CVE.Descriptions),
		})
	}
	return cves
}

func pickDescription(descriptions []nvdDescription) string {
	for _, desc := range descriptions {
		if strings.EqualFold(desc.Lang, "en") {
			return strings.TrimSpace(desc.Value)
		}
	}
	if len(descriptions) > 0 {
		return strings.TrimSpace(descriptions[0].Value)
	}
	return ""
}

func pickSeverity(metrics nvdMetrics) string {
	if severity := metricSeverity(metrics.CVSSMetricV31); severity != "" {
		return severity
	}
	if severity := metricSeverity(metrics.CVSSMetricV30); severity != "" {
		return severity
	}
	return metricSeverity(metrics.CVSSMetricV2)
}

func metricSeverity(metrics []nvdMetric) string {
	for _, metric := range metrics {
		if strings.TrimSpace(metric.CVSSData.BaseSeverity) != "" {
			return strings.TrimSpace(metric.CVSSData.BaseSeverity)
		}
	}
	return ""
}
