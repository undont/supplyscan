package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/undont/supplyscan/internal/types"
)

const (
	// defaultOSVQueryURL is the OSV.dev batched query endpoint.
	defaultOSVQueryURL = "https://api.osv.dev/v1/querybatch"

	// defaultOSVVulnURL is the OSV.dev single-vulnerability endpoint; the OSV id
	// is appended to it during hydration.
	defaultOSVVulnURL = "https://api.osv.dev/v1/vulns/"

	// osvMaxBatch is the per-request query cap (OSV allows up to 1000).
	osvMaxBatch = 1000

	// osvHydrateConcurrency bounds concurrent vuln-detail fetches.
	osvHydrateConcurrency = 8

	// osv ecosystem names, using osv.dev's exact casing.
	osvEcosystemPyPI = "PyPI"
	osvEcosystemNPM  = "npm"
)

// OSVClient audits dependencies for known vulnerabilities via OSV.dev, which
// spans npm, PyPI and more in a single API. querybatch returns only vuln ids per
// query, so confirmed hits are hydrated through the per-vuln endpoint to recover
// severity, title and fixed versions.
type OSVClient struct {
	httpClient *http.Client
	queryURL   string
	vulnURL    string
}

// OSVOption configures an OSVClient.
type OSVOption func(*OSVClient)

// WithOSVHTTPClient sets a custom HTTP client.
func WithOSVHTTPClient(c *http.Client) OSVOption {
	return func(client *OSVClient) {
		client.httpClient = c
	}
}

// WithOSVURLs sets custom query and vuln endpoints (for testing).
func WithOSVURLs(queryURL, vulnURL string) OSVOption {
	return func(client *OSVClient) {
		client.queryURL = queryURL
		client.vulnURL = vulnURL
	}
}

// NewOSVClient creates a new OSV.dev audit client.
func NewOSVClient(opts ...OSVOption) *OSVClient {
	c := &OSVClient{
		httpClient: &http.Client{Timeout: defaultTimeout},
		queryURL:   defaultOSVQueryURL,
		vulnURL:    defaultOSVVulnURL,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// osvAuditEcosystem maps our internal ecosystem id onto the OSV ecosystem name.
func osvAuditEcosystem(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case types.EcosystemPyPI:
		return osvEcosystemPyPI
	case "", types.EcosystemNPM:
		return osvEcosystemNPM
	default:
		return ecosystem
	}
}

// AuditDependencies audits a list of dependencies, returning one finding per
// (package, version, vulnerability).
func (c *OSVClient) AuditDependencies(deps []types.Dependency) ([]types.VulnerabilityFinding, error) {
	if len(deps) == 0 {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	// Query in batches; refs[i] holds the vuln ids matched for deps[i].
	refs := make([][]string, len(deps))
	idSet := make(map[string]struct{})
	for start := 0; start < len(deps); start += osvMaxBatch {
		end := min(start+osvMaxBatch, len(deps))
		results, err := c.queryBatch(ctx, deps[start:end])
		if err != nil {
			return nil, err
		}
		for i, res := range results {
			for _, v := range res.Vulns {
				refs[start+i] = append(refs[start+i], v.ID)
				idSet[v.ID] = struct{}{}
			}
		}
	}

	if len(idSet) == 0 {
		return nil, nil
	}

	details, err := c.hydrate(ctx, idSet)
	if err != nil {
		return nil, err
	}

	return buildOSVFindings(deps, refs, details), nil
}

// AuditSinglePackage audits a single package and returns simplified records.
func (c *OSVClient) AuditSinglePackage(ecosystem, name, version string) ([]types.VulnerabilityInfo, error) {
	deps := []types.Dependency{{Name: name, Version: version, Ecosystem: ecosystem}}
	findings, err := c.AuditDependencies(deps)
	if err != nil {
		return nil, err
	}

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

// osvQuery is a single querybatch query.
type osvQuery struct {
	Package osvQueryPackage `json:"package"`
	Version string          `json:"version"`
}

type osvQueryPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvBatchResponse struct {
	Results []osvBatchResult `json:"results"`
}

type osvBatchResult struct {
	Vulns []osvVulnRef `json:"vulns"`
}

type osvVulnRef struct {
	ID string `json:"id"`
}

// queryBatch posts one batch of queries and returns per-query results in order.
func (c *OSVClient) queryBatch(ctx context.Context, deps []types.Dependency) ([]osvBatchResult, error) {
	queries := make([]osvQuery, 0, len(deps))
	for _, d := range deps {
		name := d.Name
		if strings.EqualFold(d.Ecosystem, types.EcosystemPyPI) {
			name = types.NormalizePyPIName(name)
		}
		queries = append(queries, osvQuery{
			Package: osvQueryPackage{Ecosystem: osvAuditEcosystem(d.Ecosystem), Name: name},
			Version: d.Version,
		})
	}

	body, err := json.Marshal(osvBatchRequest{Queries: queries})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OSV query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.queryURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create OSV request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OSV query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV query returned status %d", resp.StatusCode)
	}

	var batch osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batch); err != nil {
		return nil, fmt.Errorf("failed to decode OSV response: %w", err)
	}

	// OSV guarantees results align with queries by index; pad defensively.
	if len(batch.Results) < len(deps) {
		batch.Results = append(batch.Results, make([]osvBatchResult, len(deps)-len(batch.Results))...)
	}
	return batch.Results, nil
}

// osvVulnDetail is the subset of a hydrated OSV record we use.
type osvVulnDetail struct {
	ID               string                     `json:"id"`
	Summary          string                     `json:"summary"`
	Aliases          []string                   `json:"aliases"`
	Severity         []osvSeverityEntry         `json:"severity"`
	Affected         []osvAffectedEntry         `json:"affected"`
	DatabaseSpecific map[string]json.RawMessage `json:"database_specific"`
}

type osvSeverityEntry struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffectedEntry struct {
	Package          osvQueryPackage            `json:"package"`
	Ranges           []osvAffectedRange         `json:"ranges"`
	DatabaseSpecific map[string]json.RawMessage `json:"database_specific"`
}

type osvAffectedRange struct {
	Events []osvRangeEvent `json:"events"`
}

type osvRangeEvent struct {
	Fixed string `json:"fixed"`
}

// hydrate fetches full records for the given vuln ids concurrently.
func (c *OSVClient) hydrate(ctx context.Context, ids map[string]struct{}) (map[string]*osvVulnDetail, error) {
	details := make(map[string]*osvVulnDetail, len(ids))
	var mu sync.Mutex

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(osvHydrateConcurrency)
	for id := range ids {
		g.Go(func() error {
			d, err := c.fetchVuln(gctx, id)
			if err != nil {
				return nil // best-effort: skip entries that fail to hydrate
			}
			mu.Lock()
			details[id] = d
			mu.Unlock()
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return details, nil
}

// fetchVuln retrieves a single OSV record by id.
func (c *OSVClient) fetchVuln(ctx context.Context, id string) (*osvVulnDetail, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.vulnURL+id, http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV vuln %s returned status %d", id, resp.StatusCode)
	}

	var detail osvVulnDetail
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		return nil, err
	}
	return &detail, nil
}

// buildOSVFindings converts hydrated records into vulnerability findings.
func buildOSVFindings(deps []types.Dependency, refs [][]string, details map[string]*osvVulnDetail) []types.VulnerabilityFinding {
	var findings []types.VulnerabilityFinding
	for i, dep := range deps {
		for _, id := range refs[i] {
			detail, ok := details[id]
			if !ok {
				continue
			}
			findings = append(findings, types.VulnerabilityFinding{
				Severity:         osvSeverity(detail, &dep),
				Package:          dep.Name,
				InstalledVersion: dep.Version,
				ID:               detail.ID,
				Title:            osvTitle(detail),
				PatchedIn:        osvPatchedIn(detail, &dep),
			})
		}
	}
	return findings
}

// osvTitle picks the best human-readable title for a record.
func osvTitle(detail *osvVulnDetail) string {
	if detail.Summary != "" {
		return detail.Summary
	}
	return detail.ID
}

// osvSeverity resolves a record's severity, preferring a textual label and
// falling back to the highest CVSS v3 base score across severity entries.
func osvSeverity(detail *osvVulnDetail, dep *types.Dependency) string {
	if s := severityFromLabel(databaseSpecificSeverity(detail.DatabaseSpecific)); s != "" {
		return s
	}
	if aff := matchingAffected(detail, dep); aff != nil {
		if s := severityFromLabel(databaseSpecificSeverity(aff.DatabaseSpecific)); s != "" {
			return s
		}
	}

	best := ""
	bestScore := 0.0
	for _, entry := range detail.Severity {
		if !strings.HasPrefix(entry.Type, "CVSS_V3") {
			continue
		}
		score, ok := cvssV3BaseScore(entry.Score)
		if !ok {
			continue
		}
		if s := severityFromScore(score); s != "" && score >= bestScore {
			best, bestScore = s, score
		}
	}
	if best != "" {
		return best
	}
	return types.SeverityUnknown
}

// databaseSpecificSeverity extracts a "severity" string from a database_specific
// blob, tolerating that the field may be absent or non-string.
func databaseSpecificSeverity(ds map[string]json.RawMessage) string {
	raw, ok := ds["severity"]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// osvPatchedIn returns a comma-joined list of fixed versions for the matching
// affected entry, or "" if none are recorded.
func osvPatchedIn(detail *osvVulnDetail, dep *types.Dependency) string {
	aff := matchingAffected(detail, dep)
	if aff == nil {
		return ""
	}
	var fixed []string
	seen := make(map[string]bool)
	for _, r := range aff.Ranges {
		for _, e := range r.Events {
			if e.Fixed != "" && !seen[e.Fixed] {
				seen[e.Fixed] = true
				fixed = append(fixed, e.Fixed)
			}
		}
	}
	return strings.Join(fixed, ", ")
}

// matchingAffected finds the affected entry for the dependency's package,
// matching ecosystem and (PEP 503-normalised) name.
func matchingAffected(detail *osvVulnDetail, dep *types.Dependency) *osvAffectedEntry {
	wantEco := osvAuditEcosystem(dep.Ecosystem)
	wantName := dep.Name
	if strings.EqualFold(dep.Ecosystem, types.EcosystemPyPI) {
		wantName = types.NormalizePyPIName(wantName)
	}
	for i := range detail.Affected {
		aff := &detail.Affected[i]
		if aff.Package.Ecosystem != wantEco {
			continue
		}
		name := aff.Package.Name
		if wantEco == osvEcosystemPyPI {
			name = types.NormalizePyPIName(name)
		}
		if name == wantName {
			return aff
		}
	}
	return nil
}
