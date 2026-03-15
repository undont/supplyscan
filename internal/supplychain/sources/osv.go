package sources

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/seanhalberthal/supplyscan/internal/types"
)

const (
	// osvZipURL is the GCS URL for the npm ecosystem bulk zip containing all advisories.
	osvZipURL = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"

	// osvCacheTTL is the cache TTL for OSV data (12 hours).
	osvCacheTTL = 12 * time.Hour

	// osvSourceName is the source identifier.
	osvSourceName = "osv"

	// osvCampaign is the campaign identifier for OSV malware advisories.
	osvCampaign = "osv-malware"

	// osvMalwarePrefix is the filename prefix for malware advisories in the zip.
	osvMalwarePrefix = "MAL-"
)

// OSVSource fetches malware advisories from the OSV.dev database via the
// npm ecosystem bulk zip from the public GCS data bucket. It filters for
// MAL- prefixed entries (malware advisories) and extracts package data.
//
// This approach downloads a single zip file instead of making thousands of
// individual HTTP requests, which is dramatically faster when the bucket
// contains hundreds of thousands of entries.
type OSVSource struct {
	zipURL string
}

// OSVSourceOption configures an OSVSource.
type OSVSourceOption func(*OSVSource)

// WithOSVZipURL sets a custom zip URL (for testing).
func WithOSVZipURL(url string) OSVSourceOption {
	return func(s *OSVSource) {
		s.zipURL = url
	}
}

// NewOSVSource creates a new OSV.dev IOC source.
func NewOSVSource(opts ...OSVSourceOption) *OSVSource {
	s := &OSVSource{
		zipURL: osvZipURL,
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

// Fetch retrieves npm malware advisories by downloading the bulk ecosystem
// zip and filtering for MAL- prefixed entries.
func (s *OSVSource) Fetch(ctx context.Context, client *http.Client) (*types.SourceData, error) {
	zipData, err := s.downloadZip(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("failed to download OSV zip: %w", err)
	}

	packages, err := processZip(zipData)
	if err != nil {
		return nil, fmt.Errorf("failed to process OSV zip: %w", err)
	}

	return &types.SourceData{
		Source:    s.Name(),
		Campaign:  osvCampaign,
		Packages:  packages,
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// downloadZip fetches the bulk ecosystem zip from GCS.
func (s *OSVSource) downloadZip(ctx context.Context, client *http.Client) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.zipURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req) //nolint:gosec // URL is the configured OSV GCS endpoint
	if err != nil {
		return nil, fmt.Errorf("failed to fetch zip: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
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

// processZip reads a zip archive and extracts malware advisory data from MAL- prefixed entries.
func processZip(data []byte) (map[string]types.SourcePackage, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("failed to open zip: %w", err)
	}

	packages := make(map[string]types.SourcePackage)

	for _, file := range reader.File {
		name := path.Base(file.Name)
		if !strings.HasPrefix(name, osvMalwarePrefix) || !strings.HasSuffix(name, ".json") {
			continue
		}

		vuln, err := readZipEntry(file)
		if err != nil {
			continue // skip individual entry errors
		}

		mergeOSVVulnerability(packages, vuln)
	}

	return packages, nil
}

// readZipEntry opens and decodes a single zip entry as an OSV vulnerability.
func readZipEntry(file *zip.File) (*osvVulnerability, error) {
	rc, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	var vuln osvVulnerability
	if err := json.NewDecoder(rc).Decode(&vuln); err != nil {
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
