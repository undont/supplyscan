package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/seanhalberthal/supplyscan/internal/types"
)

const (
	// osvGCSListURL is the GCS JSON API endpoint for listing objects in the OSV bucket.
	osvGCSListURL = "https://storage.googleapis.com/storage/v1/b/osv-vulnerabilities/o"

	// osvGCSBaseURL is the public base URL for fetching individual OSV entries.
	osvGCSBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"

	// osvCacheTTL is the cache TTL for OSV data (12 hours).
	osvCacheTTL = 12 * time.Hour

	// osvSourceName is the source identifier.
	osvSourceName = "osv"

	// osvCampaign is the campaign identifier for OSV malware advisories.
	osvCampaign = "osv-malware"

	// osvMaxEntries is the safety limit on malware entries to fetch.
	osvMaxEntries = 5000

	// osvFetchConcurrency is the max parallel fetches for individual entries.
	osvFetchConcurrency = 10
)

// OSVSource fetches malware advisories from the OSV.dev database via its
// public GCS data bucket. It specifically targets npm malware entries
// (MAL- prefixed IDs) which may include advisories from sources beyond
// GitHub's Security Advisory Database.
type OSVSource struct {
	listURL string
	baseURL string
}

// OSVSourceOption configures an OSVSource.
type OSVSourceOption func(*OSVSource)

// WithOSVListURL sets a custom GCS list URL (for testing).
func WithOSVListURL(url string) OSVSourceOption {
	return func(s *OSVSource) {
		s.listURL = url
	}
}

// WithOSVBaseURL sets a custom base URL for fetching entries (for testing).
func WithOSVBaseURL(url string) OSVSourceOption {
	return func(s *OSVSource) {
		s.baseURL = url
	}
}

// NewOSVSource creates a new OSV.dev IOC source.
func NewOSVSource(opts ...OSVSourceOption) *OSVSource {
	s := &OSVSource{
		listURL: osvGCSListURL,
		baseURL: osvGCSBaseURL,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Name returns the source identifier.
func (s *OSVSource) Name() string {
	return osvSourceName
}

// CacheTTL returns how long this source's data should be cached.
func (s *OSVSource) CacheTTL() time.Duration {
	return osvCacheTTL
}

// Fetch retrieves npm malware advisories from the OSV GCS data bucket.
func (s *OSVSource) Fetch(ctx context.Context, client *http.Client) (*types.SourceData, error) {
	// Step 1: List all MAL- entries for npm
	entryNames, err := s.listMalwareEntries(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("failed to list OSV malware entries: %w", err)
	}

	if len(entryNames) == 0 {
		return &types.SourceData{
			Source:    s.Name(),
			Campaign:  osvCampaign,
			Packages:  make(map[string]types.SourcePackage),
			FetchedAt: time.Now().UTC().Format(time.RFC3339),
		}, nil
	}

	// Step 2: Fetch entries concurrently
	packages := s.fetchEntries(ctx, client, entryNames)

	return &types.SourceData{
		Source:    s.Name(),
		Campaign:  osvCampaign,
		Packages:  packages,
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// gcsListResponse is the response from the GCS JSON API list objects endpoint.
type gcsListResponse struct {
	Items         []gcsObject `json:"items"`
	NextPageToken string      `json:"nextPageToken"`
}

// gcsObject represents an object in the GCS bucket.
type gcsObject struct {
	Name string `json:"name"`
}

// listMalwareEntries uses the GCS JSON API to list all MAL- prefixed npm entries.
func (s *OSVSource) listMalwareEntries(ctx context.Context, client *http.Client) ([]string, error) {
	var entries []string
	pageToken := ""

	for {
		url := s.listURL + "?prefix=npm/MAL-&fields=items(name),nextPageToken&maxResults=1000"
		if pageToken != "" {
			url += "&pageToken=" + pageToken
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
		if err != nil {
			return nil, fmt.Errorf("failed to create list request: %w", err)
		}

		resp, err := client.Do(req) //nolint:gosec // URL is the configured GCS list endpoint
		if err != nil {
			return nil, fmt.Errorf("failed to list objects: %w", err)
		}

		var listResp gcsListResponse
		decodeErr := json.NewDecoder(resp.Body).Decode(&listResp)
		_ = resp.Body.Close()
		if decodeErr != nil {
			return nil, fmt.Errorf("failed to decode list response: %w", decodeErr)
		}

		for _, item := range listResp.Items {
			// Only include .json files (skip directories or other artefacts)
			if strings.HasSuffix(item.Name, ".json") {
				entries = append(entries, item.Name)
			}
		}

		// Safety limit
		if len(entries) >= osvMaxEntries {
			entries = entries[:osvMaxEntries]
			break
		}

		if listResp.NextPageToken == "" {
			break
		}
		pageToken = listResp.NextPageToken
	}

	return entries, nil
}

// osvVulnerability represents an OSV vulnerability entry.
type osvVulnerability struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Aliases  []string      `json:"aliases"`
	Severity []osvSeverity `json:"severity"`
	Affected []osvAffected `json:"affected"`
}

// osvSeverity represents severity information.
type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// osvAffected represents affected package information.
type osvAffected struct {
	Package  osvPackage `json:"package"`
	Ranges   []osvRange `json:"ranges"`
	Versions []string   `json:"versions"`
}

// osvPackage represents a package reference.
type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// osvRange represents a version range.
type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

// osvEvent represents a version event in a range.
type osvEvent struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

// fetchEntries fetches individual OSV entries concurrently and builds the package map.
func (s *OSVSource) fetchEntries(ctx context.Context, client *http.Client, entryNames []string) map[string]types.SourcePackage {
	packages := make(map[string]types.SourcePackage)
	var mu sync.Mutex

	// Use a semaphore channel to limit concurrency
	sem := make(chan struct{}, osvFetchConcurrency)

	var wg sync.WaitGroup
	for _, name := range entryNames {
		wg.Add(1)
		go func(entryName string) {
			defer wg.Done()

			// Acquire semaphore
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			vuln, err := s.fetchEntry(ctx, client, entryName)
			if err != nil || vuln == nil {
				return
			}

			mu.Lock()
			mergeOSVVulnerability(packages, vuln)
			mu.Unlock()
		}(name)
	}

	wg.Wait()
	return packages
}

// fetchEntry fetches and parses a single OSV vulnerability entry.
func (s *OSVSource) fetchEntry(ctx context.Context, client *http.Client, entryName string) (*osvVulnerability, error) {
	url := s.baseURL + "/" + entryName

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req) //nolint:gosec // URL is the configured OSV GCS endpoint
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d for %s", resp.StatusCode, entryName)
	}

	var vuln osvVulnerability
	if err := json.NewDecoder(resp.Body).Decode(&vuln); err != nil {
		return nil, err
	}

	return &vuln, nil
}

// mergeOSVVulnerability extracts package data from an OSV entry and merges it into the packages map.
func mergeOSVVulnerability(packages map[string]types.SourcePackage, vuln *osvVulnerability) {
	for _, affected := range vuln.Affected {
		if affected.Package.Ecosystem != "npm" {
			continue
		}

		pkgName := affected.Package.Name
		versions := extractOSVVersions(&affected)
		advisoryID := vuln.ID

		// Check for GHSA alias
		for _, alias := range vuln.Aliases {
			if strings.HasPrefix(alias, "GHSA-") {
				advisoryID = alias
				break
			}
		}

		if existing, ok := packages[pkgName]; ok {
			existing.Versions = mergeOSVVersions(existing.Versions, versions)
			packages[pkgName] = existing
		} else {
			packages[pkgName] = types.SourcePackage{
				Name:       pkgName,
				Versions:   versions,
				AdvisoryID: advisoryID,
				Severity:   "critical", // Malware defaults to critical
			}
		}
	}
}

// extractOSVVersions extracts version info from an OSV affected entry.
func extractOSVVersions(affected *osvAffected) []string {
	// If explicit versions are listed, use them
	if len(affected.Versions) > 0 {
		return affected.Versions
	}

	// Otherwise, check ranges. For malware, "introduced: 0" with no fix
	// means all versions are malicious.
	for _, r := range affected.Ranges {
		for _, event := range r.Events {
			if event.Introduced == "0" {
				// Check if there's a corresponding fix
				hasFix := false
				for _, e := range r.Events {
					if e.Fixed != "" {
						hasFix = true
						break
					}
				}
				if !hasFix {
					// All versions affected
					return []string{">= 0"}
				}
			}
		}
	}

	return nil
}

// mergeOSVVersions merges two version lists, deduplicating.
func mergeOSVVersions(existing, newVersions []string) []string {
	seen := make(map[string]bool, len(existing))
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
