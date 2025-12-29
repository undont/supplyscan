// Package types defines shared data structures for supplyscan.
package types

import "runtime/debug"

// Version is the application version. Set at build time via -ldflags.
// Falls back to module version from go install, or "dev" for local builds.
var Version = "dev"

func init() {
	// If version wasn't set via ldflags, try to get it from build info
	// This works when installed via: go install ...@version
	if Version == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			Version = info.Main.Version
		}
	}
}

// Dependency represents a single package dependency from a lockfile.
type Dependency struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Dev      bool   `json:"dev,omitempty"`
	Optional bool   `json:"optional,omitempty"`
}

// LockfileInfo contains metadata about a parsed lockfile.
type LockfileInfo struct {
	Path         string `json:"path"`
	Type         string `json:"type"`
	Dependencies int    `json:"dependencies"`
}

// SupportedLockfiles is the list of lockfile formats we can parse.
var SupportedLockfiles = []string{
	"package-lock.json",
	"npm-shrinkwrap.json",
	"yarn.lock",
	"pnpm-lock.yaml",
	"bun.lock",
	"deno.lock",
}

// CompromisedPackage represents a known malicious package from IOC data.
type CompromisedPackage struct {
	Name        string   `json:"name"`
	Versions    []string `json:"versions"`
	Sources     []string `json:"sources"`
	Campaigns   []string `json:"campaigns,omitempty"`    // Multiple campaigns that flagged this package
	AdvisoryIDs []string `json:"advisory_ids,omitempty"` // GHSA IDs, CVE IDs, etc.
	FirstSeen   string   `json:"first_seen,omitempty"`   // When first detected (RFC3339)
}

// SupplyChainFinding represents a detected supply chain compromise.
type SupplyChainFinding struct {
	Severity            string   `json:"severity"`
	Type                string   `json:"type"`
	Package             string   `json:"package"`
	InstalledVersion    string   `json:"installed_version"`
	CompromisedVersions []string `json:"compromised_versions,omitempty"`
	SafeVersion         string   `json:"safe_version,omitempty"`
	Lockfile            string   `json:"lockfile"`
	Action              string   `json:"action"`
	Campaigns           []string `json:"campaigns,omitempty"`    // Attack campaigns that flagged this
	AdvisoryIDs         []string `json:"advisory_ids,omitempty"` // GHSA IDs, CVE IDs, etc.
	Sources             []string `json:"sources,omitempty"`      // IOC sources that reported this
}

// SupplyChainWarning represents a package from an at-risk namespace.
type SupplyChainWarning struct {
	Type             string `json:"type"`
	Package          string `json:"package"`
	InstalledVersion string `json:"installed_version"`
	Note             string `json:"note"`
}

// VulnerabilityFinding represents a known security vulnerability.
type VulnerabilityFinding struct {
	Severity         string `json:"severity"`
	Package          string `json:"package"`
	InstalledVersion string `json:"installed_version"`
	ID               string `json:"id"`
	Title            string `json:"title"`
	PatchedIn        string `json:"patched_in,omitempty"`
	Lockfile         string `json:"lockfile"`
}

// ScanSummary contains aggregated scan statistics.
type ScanSummary struct {
	LockfilesScanned  int         `json:"lockfiles_scanned"`
	TotalDependencies int         `json:"total_dependencies"`
	Issues            IssueCounts `json:"issues"`
}

// IssueCounts breaks down issues by severity.
type IssueCounts struct {
	Critical    int `json:"critical"`
	High        int `json:"high"`
	Moderate    int `json:"moderate"`
	SupplyChain int `json:"supply_chain"`
}

// ScanResult is the complete output of a security scan.
type ScanResult struct {
	Summary         ScanSummary         `json:"summary"`
	SupplyChain     SupplyChainResult   `json:"supply_chain"`
	Vulnerabilities VulnerabilityResult `json:"vulnerabilities"`
	Lockfiles       []LockfileInfo      `json:"lockfiles"`
}

// SupplyChainResult contains all supply chain findings.
type SupplyChainResult struct {
	Findings []SupplyChainFinding `json:"findings"`
	Warnings []SupplyChainWarning `json:"warnings"`
}

// VulnerabilityResult contains all vulnerability findings.
type VulnerabilityResult struct {
	Findings []VulnerabilityFinding `json:"findings"`
}

// IOCDatabase represents the cached IOC data.
type IOCDatabase struct {
	Packages    map[string]CompromisedPackage `json:"packages"`
	LastUpdated string                        `json:"last_updated"`
	Sources     []string                      `json:"sources"`
}

// IOCMeta contains metadata about the IOC cache.
type IOCMeta struct {
	LastUpdated    string                      `json:"last_updated"`
	ETag           string                      `json:"etag,omitempty"`
	PackageCount   int                         `json:"package_count"`
	VersionCount   int                         `json:"version_count"`
	SourceStatuses map[string]SourceStatusInfo `json:"source_statuses,omitempty"` // Per-source status
}

// SourceStatusInfo contains status information for a single IOC source.
type SourceStatusInfo struct {
	LastFetched  string `json:"last_fetched"`
	Success      bool   `json:"success"`
	Error        string `json:"error,omitempty"`
	PackageCount int    `json:"package_count"`
}

// StatusResponse is the output of the status tool.
type StatusResponse struct {
	Version            string            `json:"version"`
	IOCDatabase        IOCDatabaseStatus `json:"ioc_database"`
	SupportedLockfiles []string          `json:"supported_lockfiles"`
}

// IOCDatabaseStatus reports on the IOC database state.
type IOCDatabaseStatus struct {
	Packages      int                         `json:"packages"`
	Versions      int                         `json:"versions"`
	LastUpdated   string                      `json:"last_updated"`
	Sources       []string                    `json:"sources"`
	SourceDetails map[string]SourceStatusInfo `json:"source_details,omitempty"` // Per-source details
}

// CheckResult is the output of checking a single package.
type CheckResult struct {
	SupplyChain     CheckSupplyChainResult `json:"supply_chain"`
	Vulnerabilities []VulnerabilityInfo    `json:"vulnerabilities"`
}

// CheckSupplyChainResult indicates if a package is compromised.
type CheckSupplyChainResult struct {
	Compromised bool     `json:"compromised"`
	Campaign    string   `json:"campaign,omitempty"`     // Deprecated: use Campaigns instead
	Campaigns   []string `json:"campaigns,omitempty"`    // Attack campaigns that flagged this
	AdvisoryIDs []string `json:"advisory_ids,omitempty"` // GHSA IDs, CVE IDs, etc.
	Sources     []string `json:"sources,omitempty"`      // IOC sources that reported this
}

// VulnerabilityInfo is a simplified vulnerability record.
type VulnerabilityInfo struct {
	ID        string `json:"id"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	PatchedIn string `json:"patched_in,omitempty"`
}

// RefreshResult is the output of refreshing the IOC database.
type RefreshResult struct {
	Updated       bool                         `json:"updated"`
	PackagesCount int                          `json:"packages_count"`
	VersionsCount int                          `json:"versions_count"`
	CacheAgeHours int                          `json:"cache_age_hours"`
	SourceResults map[string]SourceRefreshInfo `json:"source_results,omitempty"` // Per-source refresh results
}

// SourceRefreshInfo contains the result of refreshing a single IOC source.
type SourceRefreshInfo struct {
	Name         string `json:"name"`
	Updated      bool   `json:"updated"`
	PackageCount int    `json:"package_count"`
	Error        string `json:"error,omitempty"`
}

// SourceData contains IOC data retrieved from a single source.
type SourceData struct {
	// Source is the name of the IOC provider (e.g., "datadog", "github").
	Source string `json:"source"`

	// Campaign identifies the attack campaign (e.g., "shai-hulud-v2", "GHSA-xxx").
	Campaign string `json:"campaign"`

	// Packages maps package names to their compromised version information.
	Packages map[string]SourcePackage `json:"packages"`

	// FetchedAt is when this data was retrieved.
	FetchedAt string `json:"fetched_at"`
}

// SourcePackage represents a compromised package from a single source.
type SourcePackage struct {
	// Name is the npm package name (e.g., "lodash", "@ctrl/tinycolor").
	Name string `json:"name"`

	// Versions lists the compromised versions.
	Versions []string `json:"versions"`

	// AdvisoryID is an optional identifier (e.g., "GHSA-xxx", "CVE-xxx").
	AdvisoryID string `json:"advisory_id,omitempty"`

	// Severity indicates the threat level (e.g., "critical", "high").
	Severity string `json:"severity,omitempty"`
}
