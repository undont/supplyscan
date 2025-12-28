package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/seanhalberthal/supplyscan/internal/types"
)

const (
	// gitHubAdvisoryURL is the GitHub Security Advisory API endpoint.
	gitHubAdvisoryURL = "https://api.github.com/advisories"

	// gitHubCacheTTL is the cache TTL for GitHub advisories (12 hours due to rate limiting).
	gitHubCacheTTL = 12 * time.Hour

	// gitHubCampaign is the campaign identifier for GitHub advisories.
	gitHubCampaign = "github-advisory"

	// gitHubPageSize is the number of advisories per page.
	gitHubPageSize = 100
)

// GitHubAdvisorySource fetches malware advisories from GitHub's Security Advisory Database.
type GitHubAdvisorySource struct {
	url   string
	token string // Optional GitHub token for higher rate limits
}

// GitHubSourceOption configures a GitHubAdvisorySource.
type GitHubSourceOption func(*GitHubAdvisorySource)

// withGitHubURL sets a custom URL for the GitHub source.
func withGitHubURL(ghURL string) GitHubSourceOption {
	return func(s *GitHubAdvisorySource) {
		s.url = ghURL
	}
}

// withGitHubToken sets a GitHub token for authenticated requests.
func withGitHubToken(ghToken string) GitHubSourceOption {
	return func(s *GitHubAdvisorySource) {
		s.token = ghToken
	}
}

// NewGitHubAdvisorySource creates a new GitHub Advisory IOC source.
func NewGitHubAdvisorySource(opts ...GitHubSourceOption) *GitHubAdvisorySource {
	s := &GitHubAdvisorySource{
		url: gitHubAdvisoryURL,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Name returns the source identifier.
func (s *GitHubAdvisorySource) Name() string {
	return "github"
}

// CacheTTL returns how long this source's data should be cached.
func (s *GitHubAdvisorySource) CacheTTL() time.Duration {
	return gitHubCacheTTL
}

// Fetch retrieves malware advisories from the GitHub Advisory Database.
func (s *GitHubAdvisorySource) Fetch(ctx context.Context, client *http.Client) (*types.SourceData, error) {
	packages := make(map[string]types.SourcePackage)
	cursor := ""

	for {
		advisories, nextCursor, err := s.fetchPage(ctx, client, cursor)
		if err != nil {
			// If we have some data, return it even if pagination failed
			if len(packages) > 0 {
				break
			}
			return nil, err
		}

		// Process advisories
		for i := range advisories {
			s.mergeAdvisoryIntoPackages(packages, &advisories[i])
		}

		// Check for more pages
		if nextCursor == "" || len(advisories) < gitHubPageSize {
			break
		}
		cursor = nextCursor
	}

	return &types.SourceData{
		Source:    s.Name(),
		Campaign:  gitHubCampaign,
		Packages:  packages,
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// fetchPage fetches a single page of advisories.
func (s *GitHubAdvisorySource) fetchPage(ctx context.Context, client *http.Client, cursor string) ([]gitHubAdvisory, string, error) {
	// Build URL with query parameters
	u, err := url.Parse(s.url)
	if err != nil {
		return nil, "", fmt.Errorf("invalid URL: %w", err)
	}

	q := u.Query()
	q.Set("ecosystem", "npm")
	q.Set("type", "malware")
	q.Set("per_page", fmt.Sprintf("%d", gitHubPageSize))
	if cursor != "" {
		q.Set("after", cursor)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch advisories: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, "", fmt.Errorf("rate limited by GitHub API (status %d)", resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var advisories []gitHubAdvisory
	if err := json.NewDecoder(resp.Body).Decode(&advisories); err != nil {
		return nil, "", fmt.Errorf("failed to decode response: %w", err)
	}

	// Extract cursor for pagination from Link header
	nextCursor := extractNextCursor(resp.Header.Get("Link"))

	return advisories, nextCursor, nil
}

// gitHubAdvisory represents a GitHub Security Advisory.
type gitHubAdvisory struct {
	GHSAID          string                `json:"ghsa_id"`
	CVEID           string                `json:"cve_id"`
	Summary         string                `json:"summary"`
	Description     string                `json:"description"`
	Severity        string                `json:"severity"`
	PublishedAt     string                `json:"published_at"`
	UpdatedAt       string                `json:"updated_at"`
	Type            string                `json:"type"`
	Vulnerabilities []gitHubVulnerability `json:"vulnerabilities"`
}

// gitHubVulnerability represents a vulnerable package in an advisory.
type gitHubVulnerability struct {
	Package                gitHubPackage `json:"package"`
	VulnerableVersionRange string        `json:"vulnerable_version_range"`
	FirstPatchedVersion    *struct {
		Identifier string `json:"identifier"`
	} `json:"first_patched_version"`
}

// gitHubPackage represents a package in an advisory.
type gitHubPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// extractNextCursor extracts the cursor for the next page from the Link header.
func extractNextCursor(linkHeader string) string {
	if linkHeader == "" {
		return ""
	}

	// Parse Link header: <url>; rel="next", <url>; rel="last"
	for _, link := range strings.Split(linkHeader, ",") {
		parts := strings.Split(strings.TrimSpace(link), ";")
		if len(parts) < 2 {
			continue
		}

		rel := strings.TrimSpace(parts[1])
		if rel == `rel="next"` {
			urlPart := strings.TrimSpace(parts[0])
			urlPart = strings.Trim(urlPart, "<>")

			// Extract "after" parameter
			if u, err := url.Parse(urlPart); err == nil {
				return u.Query().Get("after")
			}
		}
	}

	return ""
}

// parseVersionRange converts a version range string to a list of versions.
// For malware, typically the range is "= X.Y.Z" for specific versions.
func parseVersionRange(versionRange string) []string {
	versionRange = strings.TrimSpace(versionRange)
	if versionRange == "" {
		return nil
	}

	// Handle comma-separated versions: "= 1.0.0, = 1.0.1"
	var versions []string
	for _, part := range strings.Split(versionRange, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "= ") {
			version := strings.TrimPrefix(part, "= ")
			versions = append(versions, strings.TrimSpace(version))
		} else if part != "" {
			// For ranges like ">= 0" (all versions), store the range itself
			versions = append(versions, part)
		}
	}

	return versions
}

// mergeVersionRanges merges two version lists.
func mergeVersionRanges(existing []string, newRange string) []string {
	newVersions := parseVersionRange(newRange)

	seen := make(map[string]bool)
	for _, v := range existing {
		seen[v] = true
	}

	result := existing
	for _, v := range newVersions {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}

	return result
}

// normaliseSeverity normalises GitHub severity to our format.
func normaliseSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "moderate", "medium":
		return "moderate"
	case "low":
		return "low"
	default:
		return "critical" // Malware defaults to critical
	}
}

// mergeAdvisoryIntoPackages processes a single advisory and merges it into the packages map.
func (s *GitHubAdvisorySource) mergeAdvisoryIntoPackages(packages map[string]types.SourcePackage, adv *gitHubAdvisory) {
	for j := range adv.Vulnerabilities {
		vuln := &adv.Vulnerabilities[j]
		if vuln.Package.Ecosystem != "npm" {
			continue
		}

		pkgName := vuln.Package.Name
		if existing, ok := packages[pkgName]; ok {
			// Merge versions and advisory IDs
			existing.Versions = mergeVersionRanges(existing.Versions, vuln.VulnerableVersionRange)
			if existing.AdvisoryID != adv.GHSAID {
				// Keep the first advisory ID, could track multiple if needed
				existing.AdvisoryID = adv.GHSAID
			}
			packages[pkgName] = existing
		} else {
			packages[pkgName] = types.SourcePackage{
				Name:       pkgName,
				Versions:   parseVersionRange(vuln.VulnerableVersionRange),
				AdvisoryID: adv.GHSAID,
				Severity:   normaliseSeverity(adv.Severity),
			}
		}
	}
}
