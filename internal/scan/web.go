package scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"vibescan/internal/cve"
	"vibescan/internal/domain"
)

// WebOptions controls recursive web scanning.
type WebOptions struct {
	Recursive   bool
	Timeout     time.Duration
	MaxBodySize int64
}

// WebFetcher retrieves evidence for web technology detection.
type WebFetcher func(ctx context.Context, endpoint webEndpoint, timeout time.Duration, maxBodySize int64, client *http.Client) (webEvidence, error)

// WebScanner enriches targets with web technologies and CVEs.
type WebScanner struct {
	Scanner    Scanner
	Client     cve.Client
	HTTPClient *http.Client
	Fetcher    WebFetcher
	Options    WebOptions
}

// NewWebScanner wraps a scanner with recursive web scanning.
func NewWebScanner(scanner Scanner, client cve.Client, options WebOptions) *WebScanner {
	if options.MaxBodySize == 0 {
		options.MaxBodySize = 1 << 20
	}
	return &WebScanner{Scanner: scanner, Client: client, Options: options}
}

// Scan performs the underlying scan and optionally enriches web technologies.
func (w *WebScanner) Scan(ctx context.Context, target domain.Target) (domain.Target, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if w == nil || w.Scanner == nil {
		return target, nil
	}

	scanned, err := w.Scanner.Scan(ctx, target)
	if !w.Options.Recursive {
		return scanned, err
	}

	techs, techErr := w.scanTarget(ctx, scanned)
	if techErr != nil {
		err = errors.Join(err, techErr)
	}

	scanned.WebTechnologies = mergeWebTechnologies(scanned.WebTechnologies, techs)
	return scanned, err
}

func (w *WebScanner) scanTarget(ctx context.Context, target domain.Target) ([]domain.WebTechnology, error) {
	endpoints := collectWebEndpoints(target)
	if len(endpoints) == 0 {
		return nil, nil
	}

	fetcher := w.Fetcher
	if fetcher == nil {
		fetcher = fetchWebEvidence
	}

	var (
		allTechs []domain.WebTechnology
		err      error
	)

	for _, endpoint := range endpoints {
		if ctx.Err() != nil {
			return allTechs, ctx.Err()
		}

		evidence, fetchErr := fetcher(ctx, endpoint, w.Options.Timeout, w.Options.MaxBodySize, w.HTTPClient)
		if fetchErr != nil {
			err = errors.Join(err, fetchErr)
			continue
		}

		techs := detectWebTechnologies(evidence)
		techs, attachErr := attachTechCVEs(ctx, w.Client, techs)
		if attachErr != nil {
			err = errors.Join(err, attachErr)
		}

		allTechs = mergeWebTechnologies(allTechs, techs)
	}

	return allTechs, err
}

type webEndpoint struct {
	scheme string
	host   string
	port   int
	path   string
}

type webEvidence struct {
	headers map[string]string
	cookies []string
	body    string
}

var (
	webHTTPPorts  = map[int]struct{}{80: {}, 8000: {}, 8008: {}, 8080: {}, 8888: {}}
	webHTTPSPorts = map[int]struct{}{443: {}, 8443: {}, 9443: {}}
)

func collectWebEndpoints(target domain.Target) []webEndpoint {
	endpoints := make([]webEndpoint, 0)
	seen := make(map[string]struct{})

	host, path := splitHostPath(target.Address)
	if host == "" {
		return nil
	}

	for _, service := range target.Services {
		scheme, port := schemeForService(service)
		if scheme == "" || port == 0 {
			continue
		}
		key := fmt.Sprintf("%s:%d", scheme, port)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		endpoints = append(endpoints, webEndpoint{scheme: scheme, host: host, port: port, path: path})
	}

	for _, port := range target.Ports {
		if strings.ToLower(port.State) != "open" {
			continue
		}
		if scheme, ok := schemeForPort(port.Number); ok {
			key := fmt.Sprintf("%s:%d", scheme, port.Number)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			endpoints = append(endpoints, webEndpoint{scheme: scheme, host: host, port: port.Number, path: path})
		}
	}

	return endpoints
}

func schemeForService(service domain.Service) (string, int) {
	name := strings.ToLower(strings.TrimSpace(service.Name))
	port := service.Port
	if name == "http" {
		if port == 0 {
			port = 80
		}
		return "http", port
	}
	if name == "https" {
		if port == 0 {
			port = 443
		}
		return "https", port
	}

	return "", 0
}

func schemeForPort(port int) (string, bool) {
	if _, ok := webHTTPSPorts[port]; ok {
		return "https", true
	}
	if _, ok := webHTTPPorts[port]; ok {
		return "http", true
	}
	return "", false
}

func splitHostPath(address string) (string, string) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", "/"
	}

	parts := strings.SplitN(address, "/", 2)
	if len(parts) == 1 {
		return parts[0], "/"
	}
	return parts[0], "/" + parts[1]
}

func fetchWebEvidence(ctx context.Context, endpoint webEndpoint, timeout time.Duration, maxBodySize int64, client *http.Client) (webEvidence, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if maxBodySize <= 0 {
		maxBodySize = 1 << 20
	}
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}

	url := fmt.Sprintf("%s://%s:%d%s", endpoint.scheme, endpoint.host, endpoint.port, endpoint.path)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return webEvidence{}, err
	}
	req.Header.Set("User-Agent", "vibescan")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		return webEvidence{}, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	headers := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) == 0 {
			continue
		}
		headers[key] = strings.Join(values, ", ")
	}
	cookies := make([]string, 0, len(resp.Cookies()))
	for _, cookie := range resp.Cookies() {
		cookies = append(cookies, cookie.Name)
	}

	return webEvidence{headers: headers, cookies: cookies, body: string(body)}, nil
}

func detectWebTechnologies(e webEvidence) []domain.WebTechnology {
	techs := make([]domain.WebTechnology, 0)
	seen := make(map[string]struct{})

	add := func(name, version, category string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		key := strings.ToLower(name + "|" + version + "|" + category)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		techs = append(techs, domain.WebTechnology{Name: name, Version: version, Category: category})
	}

	serverHeader := headerValue(e.headers, "Server")
	if serverHeader != "" {
		product, version := parseProductVersion(serverHeader)
		if product == "" {
			product = serverHeader
		}
		add(product, version, "server")
	}

	poweredBy := headerValue(e.headers, "X-Powered-By")
	if poweredBy != "" {
		for _, token := range strings.Split(poweredBy, ",") {
			product, version := parseProductVersion(token)
			if product == "" {
				product = strings.TrimSpace(token)
			}
			add(product, version, "framework")
		}
	}

	generatorHeader := headerValue(e.headers, "X-Generator")
	if generatorHeader != "" {
		product, version := parseProductVersion(generatorHeader)
		if product == "" {
			product = generatorHeader
		}
		add(product, version, "cms")
	}

	if headerValue(e.headers, "X-Drupal-Cache") != "" {
		add("Drupal", "", "cms")
	}

	for _, cookie := range e.cookies {
		name := strings.ToLower(cookie)
		switch {
		case strings.HasPrefix(name, "wordpress") || strings.HasPrefix(name, "wp-"):
			add("WordPress", "", "cms")
		case strings.Contains(name, "drupal"):
			add("Drupal", "", "cms")
		case strings.Contains(name, "joomla"):
			add("Joomla", "", "cms")
		}
	}

	bodyLower := strings.ToLower(e.body)
	if bodyLower != "" {
		if meta := parseGeneratorMeta(e.body); meta != "" {
			product, version := parseProductVersion(meta)
			if product == "" {
				product = meta
			}
			add(product, version, "cms")
		}

		if strings.Contains(bodyLower, "wp-content") || strings.Contains(bodyLower, "wp-includes") {
			add("WordPress", "", "cms")
		}
		if strings.Contains(bodyLower, "drupal") && strings.Contains(bodyLower, "drupal.js") {
			add("Drupal", "", "cms")
		}
		if strings.Contains(bodyLower, "joomla") && strings.Contains(bodyLower, "media/system") {
			add("Joomla", "", "cms")
		}
	}

	return techs
}

func attachTechCVEs(ctx context.Context, client cve.Client, techs []domain.WebTechnology) ([]domain.WebTechnology, error) {
	if client == nil || len(techs) == 0 {
		return techs, nil
	}

	updated := make([]domain.WebTechnology, len(techs))
	copy(updated, techs)

	var errs error
	for i, tech := range updated {
		if ctx.Err() != nil {
			return updated, ctx.Err()
		}

		if strings.TrimSpace(tech.Version) == "" {
			continue
		}

		service := domain.Service{Product: tech.Name, Version: tech.Version, Name: tech.Name}
		cves, err := client.FindByService(ctx, service)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		tech.CVEs = cves
		updated[i] = tech
	}

	return updated, errs
}

func mergeWebTechnologies(existing, incoming []domain.WebTechnology) []domain.WebTechnology {
	if len(existing) == 0 {
		return incoming
	}
	if len(incoming) == 0 {
		return existing
	}

	merged := make([]domain.WebTechnology, 0, len(existing)+len(incoming))
	index := make(map[string]int)
	add := func(tech domain.WebTechnology) {
		key := strings.ToLower(tech.Name + "|" + tech.Version + "|" + tech.Category)
		if idx, ok := index[key]; ok {
			if len(tech.CVEs) > 0 {
				merged[idx].CVEs = append(merged[idx].CVEs, tech.CVEs...)
			}
			return
		}
		index[key] = len(merged)
		merged = append(merged, tech)
	}

	for _, tech := range existing {
		add(tech)
	}
	for _, tech := range incoming {
		add(tech)
	}

	return merged
}

var generatorMetaPattern = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)

func parseGeneratorMeta(body string) string {
	match := generatorMetaPattern.FindStringSubmatch(body)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func headerValue(headers map[string]string, key string) string {
	if len(headers) == 0 || key == "" {
		return ""
	}
	for name, value := range headers {
		if strings.EqualFold(name, key) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
