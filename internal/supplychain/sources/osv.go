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
	"slices"
	"strings"
	"time"

	"github.com/undont/supplyscan/internal/types"
)

const (
	// osvNPMZipURL is the GCS URL for the npm ecosystem bulk zip.
	osvNPMZipURL = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"

	// osvPyPIZipURL is the GCS URL for the PyPI ecosystem bulk zip.
	osvPyPIZipURL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"

	// osvCacheTTL is the cache TTL for OSV data (12 hours).
	osvCacheTTL = 12 * time.Hour

	// osvSourceName is the source identifier.
	osvSourceName = "osv"

	// osvCampaign is the campaign identifier for OSV malware advisories.
	osvCampaign = "osv-malware"

	// osvMalwarePrefix is the filename prefix for malware advisories in the zip.
	osvMalwarePrefix = "MAL-"

	// OSV ecosystem identifiers as they appear in the affected package data.
	osvEcosystemNPM  = "npm"
	osvEcosystemPyPI = "PyPI"
)

// OSVSource fetches malware advisories from the OSV.dev database via per-
// ecosystem bulk zips from the public GCS data bucket. It filters for MAL-
// prefixed entries (malware advisories) and extracts package data across the
// npm and PyPI ecosystems, both of which the 2026 worm campaigns target.
//
// Downloading the bulk zips avoids making thousands of individual HTTP requests,
// which is dramatically faster when the buckets contain hundreds of thousands of
// entries.
type OSVSource struct {
	npmZipURL  string
	pypiZipURL string
}

// OSVSourceOption configures an OSVSource.
type OSVSourceOption func(*OSVSource)

// WithOSVZipURL sets a custom npm zip URL and disables the PyPI fetch (for
// single-ecosystem tests).
func WithOSVZipURL(url string) OSVSourceOption {
	return func(s *OSVSource) {
		s.npmZipURL = url
		s.pypiZipURL = ""
	}
}

// WithOSVPyPIZipURL sets a custom PyPI zip URL (for testing).
func WithOSVPyPIZipURL(url string) OSVSourceOption {
	return func(s *OSVSource) {
		s.pypiZipURL = url
	}
}

// NewOSVSource creates a new OSV.dev IOC source.
func NewOSVSource(opts ...OSVSourceOption) *OSVSource {
	s := &OSVSource{
		npmZipURL:  osvNPMZipURL,
		pypiZipURL: osvPyPIZipURL,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// ecosystemKey builds the per-source map key, scoped by ecosystem so npm and
// PyPI packages of the same name don't collide within a single source.
func ecosystemKey(ecosystem, name string) string {
	return strings.ToLower(ecosystem) + ":" + name
}

// Name returns the source identifier.
func (s *OSVSource) Name() string {
	return osvSourceName
}

// CacheTTL returns how long this source's data should be cached.
func (s *OSVSource) CacheTTL() time.Duration {
	return osvCacheTTL
}

// Fetch retrieves npm and PyPI malware advisories by downloading the bulk
// ecosystem zips and filtering for MAL- prefixed entries.
func (s *OSVSource) Fetch(ctx context.Context, client *http.Client) (*types.SourceData, error) {
	ecosystems := []struct{ ecosystem, url string }{
		{osvEcosystemNPM, s.npmZipURL},
		{osvEcosystemPyPI, s.pypiZipURL},
	}

	packages := make(map[string]types.SourcePackage)
	var fetched int

	for _, e := range ecosystems {
		if e.url == "" {
			continue
		}

		zipData, err := s.downloadZip(ctx, client, e.url)
		if err != nil {
			return nil, fmt.Errorf("failed to download OSV %s zip: %w", e.ecosystem, err)
		}

		eco, err := processZip(zipData, e.ecosystem)
		if err != nil {
			return nil, fmt.Errorf("failed to process OSV %s zip: %w", e.ecosystem, err)
		}

		for k, v := range eco {
			packages[k] = v
		}
		fetched++
	}

	if fetched == 0 {
		return nil, fmt.Errorf("no OSV ecosystem zip URLs configured")
	}

	return &types.SourceData{
		Source:    s.Name(),
		Campaign:  osvCampaign,
		Packages:  packages,
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// downloadZip fetches a bulk ecosystem zip from GCS.
func (s *OSVSource) downloadZip(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
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

// processZip reads a zip archive and extracts malware advisory data from MAL-
// prefixed entries for the given ecosystem.
func processZip(data []byte, ecosystem string) (map[string]types.SourcePackage, error) {
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

		mergeOSVVulnerability(packages, vuln, ecosystem)
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

// mergeOSVVulnerability extracts package data from an OSV entry and merges it
// into the packages map, keeping only entries for the requested ecosystem.
func mergeOSVVulnerability(packages map[string]types.SourcePackage, vuln *osvVulnerability, ecosystem string) {
	for _, affected := range vuln.Affected {
		if affected.Package.Ecosystem != ecosystem {
			continue
		}

		pkgName := affected.Package.Name
		eco := strings.ToLower(ecosystem)
		if eco == types.EcosystemPyPI {
			pkgName = types.NormalizePyPIName(pkgName)
		}
		key := ecosystemKey(ecosystem, pkgName)
		versions := extractOSVVersions(&affected)
		advisoryID := vuln.ID

		// Check for GHSA alias
		for _, alias := range vuln.Aliases {
			if strings.HasPrefix(alias, "GHSA-") {
				advisoryID = alias
				break
			}
		}

		if existing, ok := packages[key]; ok {
			existing.Versions = mergeOSVVersions(existing.Versions, versions)
			packages[key] = existing
		} else {
			packages[key] = types.SourcePackage{
				Name:       pkgName,
				Ecosystem:  eco,
				Versions:   versions,
				AdvisoryID: advisoryID,
				Severity:   severityCritical, // Malware defaults to critical
			}
		}
	}
}

// extractOSVVersions extracts version info from an OSV affected entry.
func extractOSVVersions(affected *osvAffected) []string {
	if len(affected.Versions) > 0 {
		return affected.Versions
	}
	// For malware, an "introduced: 0" event with no corresponding fix means
	// every version is malicious.
	if slices.ContainsFunc(affected.Ranges, rangeCoversAllVersions) {
		return []string{">= 0"}
	}
	return nil
}

// rangeCoversAllVersions reports whether a range has an "introduced: 0" event
// without any matching "fixed" event.
func rangeCoversAllVersions(r osvRange) bool {
	introducedAtZero, hasFix := false, false
	for _, e := range r.Events {
		if e.Introduced == "0" {
			introducedAtZero = true
		}
		if e.Fixed != "" {
			hasFix = true
		}
	}
	return introducedAtZero && !hasFix
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
