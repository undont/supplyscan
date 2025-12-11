// Package audit provides npm registry audit API integration.
package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/seanhalberthal/supplyscan-mcp/internal/types"
)

// defaultEndpoint is the npm registry audit endpoint.
const defaultEndpoint = "https://registry.npmjs.org/-/npm/v1/security/audits"

// Client handles npm audit API requests.
type Client struct {
	httpClient *http.Client
	endpoint   string
}

// Option configures a Client.
type Option func(*Client)

// withHTTPClient sets a custom HTTP client.
func withHTTPClient(c *http.Client) Option {
	return func(client *Client) {
		client.httpClient = c
	}
}

// withEndpoint sets a custom audit endpoint.
func withEndpoint(endpoint string) Option {
	return func(client *Client) {
		client.endpoint = endpoint
	}
}

// NewClient creates a new npm audit client.
func NewClient(opts ...Option) *Client {
	c := &Client{
		httpClient: &http.Client{},
		endpoint:   defaultEndpoint,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// request is the request body for the npm audit API.
type request struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Requires     map[string]string `json:"requires"`
	Dependencies map[string]dep    `json:"dependencies"`
}

// dep represents a dependency in the audit request.
type dep struct {
	Version  string            `json:"version"`
	Requires map[string]string `json:"requires,omitempty"`
}

// response is the response from the npm audit API.
type response struct {
	Advisories map[string]advisory `json:"advisories"`
	Metadata   metadata            `json:"metadata"`
}

// advisory represents a security advisory.
type advisory struct {
	ID                 int       `json:"id"`
	Title              string    `json:"title"`
	ModuleName         string    `json:"module_name"`
	Severity           string    `json:"severity"`
	URL                string    `json:"url"`
	VulnerableVersions string    `json:"vulnerable_versions"`
	PatchedVersions    string    `json:"patched_versions"`
	Overview           string    `json:"overview"`
	GHSAID             string    `json:"github_advisory_id"`
	CWE                []string  `json:"cwe"`
	Findings           []finding `json:"findings"`
}

// finding represents where a vulnerability was found.
type finding struct {
	Version string   `json:"version"`
	Paths   []string `json:"paths"`
}

// metadata contains metadata about the audit.
type metadata struct {
	Vulnerabilities vulnerabilityCounts `json:"vulnerabilities"`
	Dependencies    int                 `json:"dependencies"`
}

// vulnerabilityCounts breaks down vulnerabilities by severity.
type vulnerabilityCounts struct {
	Info     int `json:"info"`
	Low      int `json:"low"`
	Moderate int `json:"moderate"`
	High     int `json:"high"`
	Critical int `json:"critical"`
}

// AuditDependencies audits a list of dependencies.
func (c *Client) AuditDependencies(deps []types.Dependency) ([]types.VulnerabilityFinding, error) {
	if len(deps) == 0 {
		return nil, nil
	}

	// Build the audit request
	req := buildAuditRequest(deps)

	// Make the request
	resp, err := c.doAudit(req)
	if err != nil {
		return nil, err
	}

	// Convert to vulnerability findings
	return convertAdvisories(resp.Advisories), nil
}

// AuditSinglePackage audits a single package.
func (c *Client) AuditSinglePackage(name, version string) ([]types.VulnerabilityInfo, error) {
	deps := []types.Dependency{{Name: name, Version: version}}
	findings, err := c.AuditDependencies(deps)
	if err != nil {
		return nil, err
	}

	// Convert to VulnerabilityInfo
	infos := make([]types.VulnerabilityInfo, 0, len(findings))
	for _, f := range findings {
		infos = append(infos, types.VulnerabilityInfo{
			ID:        f.ID,
			Severity:  f.Severity,
			Title:     f.Title,
			PatchedIn: f.PatchedIn,
		})
	}

	return infos, nil
}

// buildAuditRequest builds the npm audit request from dependencies.
func buildAuditRequest(deps []types.Dependency) *request {
	requires := make(map[string]string)
	dependencies := make(map[string]dep)

	for _, d := range deps {
		requires[d.Name] = d.Version
		dependencies[d.Name] = dep{
			Version: d.Version,
		}
	}

	return &request{
		Name:         "audit-check",
		Version:      "1.0.0",
		Requires:     requires,
		Dependencies: dependencies,
	}
}

// doAudit makes the HTTP request to the npm audit API.
func (c *Client) doAudit(req *request) (*response, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal audit request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("audit request failed: %w", err)
	}
	defer func(Body io.ReadCloser) {
		closeErr := Body.Close()
		if closeErr != nil {
			fmt.Printf("Failed to close audit response body: %v\n", closeErr)
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("audit API returned status %d", resp.StatusCode)
	}

	var auditResp response
	if err := json.NewDecoder(resp.Body).Decode(&auditResp); err != nil {
		return nil, fmt.Errorf("failed to decode audit response: %w", err)
	}

	return &auditResp, nil
}

// convertAdvisories converts npm advisories to vulnerability findings.
func convertAdvisories(advisories map[string]advisory) []types.VulnerabilityFinding {
	findings := make([]types.VulnerabilityFinding, 0)

	for _, adv := range advisories { //nolint:gocritic // rangeValCopy: can't avoid copy when ranging over map values
		// Get affected versions from findings
		for _, f := range adv.Findings {
			finding := types.VulnerabilityFinding{
				Severity:         normaliseSeverity(adv.Severity),
				Package:          adv.ModuleName,
				InstalledVersion: f.Version,
				ID:               getAdvisoryID(&adv),
				Title:            adv.Title,
				PatchedIn:        adv.PatchedVersions,
			}
			findings = append(findings, finding)
		}

		// If no findings but advisory exists, still report it
		if len(adv.Findings) == 0 {
			finding := types.VulnerabilityFinding{
				Severity:  normaliseSeverity(adv.Severity),
				Package:   adv.ModuleName,
				ID:        getAdvisoryID(&adv),
				Title:     adv.Title,
				PatchedIn: adv.PatchedVersions,
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// normaliseSeverity normalises severity strings.
func normaliseSeverity(s string) string {
	s = strings.ToLower(s)
	switch s {
	case "critical", "high", "moderate", "low", "info":
		return s
	default:
		return "unknown"
	}
}

// getAdvisoryID returns the best identifier for an advisory.
func getAdvisoryID(adv *advisory) string {
	if adv.GHSAID != "" {
		return adv.GHSAID
	}
	return fmt.Sprintf("npm:%d", adv.ID)
}
