// Package audit provides npm registry audit API integration.
package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/seanhalberthal/supplyscan-mcp/internal/types"
)

const (
	// npm registry audit endpoint
	AuditEndpoint = "https://registry.npmjs.org/-/npm/v1/security/audits"
)

// Client handles npm audit API requests.
type Client struct {
	httpClient *http.Client
}

// NewClient creates a new npm audit client.
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{},
	}
}

// AuditRequest is the request body for the npm audit API.
type AuditRequest struct {
	Name         string                  `json:"name"`
	Version      string                  `json:"version"`
	Requires     map[string]string       `json:"requires"`
	Dependencies map[string]AuditDep     `json:"dependencies"`
}

// AuditDep represents a dependency in the audit request.
type AuditDep struct {
	Version  string            `json:"version"`
	Requires map[string]string `json:"requires,omitempty"`
}

// AuditResponse is the response from the npm audit API.
type AuditResponse struct {
	Advisories map[string]Advisory `json:"advisories"`
	Metadata   AuditMetadata       `json:"metadata"`
}

// Advisory represents a security advisory.
type Advisory struct {
	ID                 int      `json:"id"`
	Title              string   `json:"title"`
	ModuleName         string   `json:"module_name"`
	Severity           string   `json:"severity"`
	URL                string   `json:"url"`
	VulnerableVersions string   `json:"vulnerable_versions"`
	PatchedVersions    string   `json:"patched_versions"`
	Overview           string   `json:"overview"`
	GHSAID             string   `json:"github_advisory_id"`
	CWE                []string `json:"cwe"`
	Findings           []Finding `json:"findings"`
}

// Finding represents where a vulnerability was found.
type Finding struct {
	Version string   `json:"version"`
	Paths   []string `json:"paths"`
}

// AuditMetadata contains metadata about the audit.
type AuditMetadata struct {
	Vulnerabilities VulnerabilityCounts `json:"vulnerabilities"`
	Dependencies    int                 `json:"dependencies"`
}

// VulnerabilityCounts breaks down vulnerabilities by severity.
type VulnerabilityCounts struct {
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
	var infos []types.VulnerabilityInfo
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
func buildAuditRequest(deps []types.Dependency) *AuditRequest {
	requires := make(map[string]string)
	dependencies := make(map[string]AuditDep)

	for _, dep := range deps {
		requires[dep.Name] = dep.Version
		dependencies[dep.Name] = AuditDep{
			Version: dep.Version,
		}
	}

	return &AuditRequest{
		Name:         "audit-check",
		Version:      "1.0.0",
		Requires:     requires,
		Dependencies: dependencies,
	}
}

// doAudit makes the HTTP request to the npm audit API.
func (c *Client) doAudit(req *AuditRequest) (*AuditResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal audit request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", AuditEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("audit request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("audit API returned status %d", resp.StatusCode)
	}

	var auditResp AuditResponse
	if err := json.NewDecoder(resp.Body).Decode(&auditResp); err != nil {
		return nil, fmt.Errorf("failed to decode audit response: %w", err)
	}

	return &auditResp, nil
}

// convertAdvisories converts npm advisories to vulnerability findings.
func convertAdvisories(advisories map[string]Advisory) []types.VulnerabilityFinding {
	var findings []types.VulnerabilityFinding

	for _, adv := range advisories {
		// Get affected versions from findings
		for _, f := range adv.Findings {
			finding := types.VulnerabilityFinding{
				Severity:         normaliseSeverity(adv.Severity),
				Package:          adv.ModuleName,
				InstalledVersion: f.Version,
				ID:               getAdvisoryID(adv),
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
				ID:        getAdvisoryID(adv),
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
func getAdvisoryID(adv Advisory) string {
	if adv.GHSAID != "" {
		return adv.GHSAID
	}
	return fmt.Sprintf("npm:%d", adv.ID)
}