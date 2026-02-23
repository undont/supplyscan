// Package audit provides npm registry audit API integration.
package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/seanhalberthal/supplyscan/internal/types"
)

// defaultEndpoint is the npm bulk advisory endpoint (npm v7+).
const defaultEndpoint = "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk"

// defaultTimeout is the HTTP client timeout.
const defaultTimeout = 30 * time.Second

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
		httpClient: &http.Client{Timeout: defaultTimeout},
		endpoint:   defaultEndpoint,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// bulkRequest maps package names to their installed versions for the bulk advisory API.
type bulkRequest map[string][]string

// bulkAdvisory represents an advisory from the bulk advisory endpoint.
type bulkAdvisory struct {
	ID                 int      `json:"id"`
	URL                string   `json:"url"`
	Title              string   `json:"title"`
	ModuleName         string   `json:"module_name"`
	Severity           string   `json:"severity"`
	VulnerableVersions string   `json:"vulnerable_versions"`
	PatchedVersions    string   `json:"patched_versions"`
	Range              string   `json:"range"`
	GHSAID             string   `json:"github_advisory_id"`
	CWE                []string `json:"cwe"`
}

// bulkResponse maps package names to their advisories.
type bulkResponse map[string][]bulkAdvisory

// AuditDependencies audits a list of dependencies.
func (c *Client) AuditDependencies(deps []types.Dependency) ([]types.VulnerabilityFinding, error) {
	if len(deps) == 0 {
		return nil, nil
	}

	// Build the bulk request
	req := buildBulkRequest(deps)

	// Make the request
	resp, err := c.doBulkAudit(req, deps)
	if err != nil {
		return nil, err
	}

	// Convert to vulnerability findings
	return convertBulkAdvisories(resp, deps), nil
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

// buildBulkRequest builds the bulk advisory request from dependencies.
func buildBulkRequest(deps []types.Dependency) bulkRequest {
	req := make(bulkRequest)
	for _, d := range deps {
		req[d.Name] = append(req[d.Name], d.Version)
	}
	return req
}

// doBulkAudit makes the HTTP request to the npm bulk advisory API.
func (c *Client) doBulkAudit(req bulkRequest, deps []types.Dependency) (bulkResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal audit request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(httpReq) //nolint:gosec // URL is the configured npm audit endpoint
	if err != nil {
		return nil, fmt.Errorf("audit request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("audit API returned status %d", resp.StatusCode)
	}

	var bulkResp bulkResponse
	if err := json.NewDecoder(resp.Body).Decode(&bulkResp); err != nil {
		// If bulk endpoint fails, the response may not be valid JSON.
		// This can happen if the registry doesn't support the bulk endpoint.
		return nil, fmt.Errorf("failed to decode audit response: %w", err)
	}

	return bulkResp, nil
}

// convertBulkAdvisories converts bulk advisory response to vulnerability findings.
func convertBulkAdvisories(resp bulkResponse, deps []types.Dependency) []types.VulnerabilityFinding {
	findings := make([]types.VulnerabilityFinding, 0)

	// Build a set of installed versions per package for lookup
	installedVersions := make(map[string]map[string]bool)
	for _, d := range deps {
		if installedVersions[d.Name] == nil {
			installedVersions[d.Name] = make(map[string]bool)
		}
		installedVersions[d.Name][d.Version] = true
	}

	for pkgName, advisories := range resp {
		versions := installedVersions[pkgName]
		for i := range advisories {
			// Report a finding for each installed version of this package
			for version := range versions {
				finding := types.VulnerabilityFinding{
					Severity:         normaliseSeverity(advisories[i].Severity),
					Package:          pkgName,
					InstalledVersion: version,
					ID:               getBulkAdvisoryID(&advisories[i]),
					Title:            advisories[i].Title,
					PatchedIn:        advisories[i].PatchedVersions,
				}
				findings = append(findings, finding)
			}
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

// getBulkAdvisoryID returns the best identifier for a bulk advisory.
func getBulkAdvisoryID(adv *bulkAdvisory) string {
	if adv.GHSAID != "" {
		return adv.GHSAID
	}
	return fmt.Sprintf("npm:%d", adv.ID)
}
