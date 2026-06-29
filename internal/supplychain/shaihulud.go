package supplychain

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/undont/supplyscan/internal/semverutil"
	"github.com/undont/supplyscan/internal/supplychain/sources"
	"github.com/undont/supplyscan/internal/types"
)

// Detector checks packages against the IOC database.
type Detector struct {
	aggregator *aggregator
}

// DetectorOption configures a Detector.
type DetectorOption func(*detectorConfig)

type detectorConfig struct {
	httpClient *http.Client
	cacheDir   string
	sources    []IOCSource
}

// withDetectorCacheDir sets a custom cache directory.
func withDetectorCacheDir(dir string) DetectorOption {
	return func(cfg *detectorConfig) {
		cfg.cacheDir = dir
	}
}

// withDetectorSources sets custom IOC sources.
func withDetectorSources(srcs ...IOCSource) DetectorOption {
	return func(cfg *detectorConfig) {
		cfg.sources = srcs
	}
}

// NewDetector creates a new supply chain detector with multi-source support.
func NewDetector(opts ...DetectorOption) (*Detector, error) {
	cfg := &detectorConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	// Default sources: DataDog + GitHub Advisory + OSV.dev
	iocSources := cfg.sources
	if len(iocSources) == 0 {
		iocSources = []IOCSource{
			sources.NewDataDogSource(),
			sources.NewDataDogTeamPCPSource(),
			sources.NewGitHubAdvisorySource(),
			sources.NewOSVSource(),
		}
	}

	// Create aggregator options
	var aggOpts []AggregatorOption
	if cfg.httpClient != nil {
		aggOpts = append(aggOpts, withAggregatorHTTPClient(cfg.httpClient))
	}
	if cfg.cacheDir != "" {
		aggOpts = append(aggOpts, withAggregatorCacheDir(cfg.cacheDir))
	}

	agg, err := newAggregator(iocSources, aggOpts...)
	if err != nil {
		return nil, err
	}

	return &Detector{aggregator: agg}, nil
}

// EnsureLoaded loads the IOC database, refreshing if needed.
func (d *Detector) EnsureLoaded() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	return d.aggregator.ensureLoaded(ctx)
}

// Refresh forces a refresh of the IOC database.
func (d *Detector) Refresh(force bool) (*types.RefreshResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	return d.aggregator.refresh(ctx, force)
}

// normalizeEcosystem maps an empty ecosystem to npm (the historical default)
// and lowercases the rest so keys are stable.
func normalizeEcosystem(ecosystem string) string {
	if ecosystem == "" {
		return types.EcosystemNPM
	}
	return strings.ToLower(ecosystem)
}

// iocKey builds the ecosystem-scoped key used in the IOC database. Package names
// collide across registries, so lookups must include the ecosystem. PyPI names
// are normalised per PEP 503 so lockfile and IOC names line up.
func iocKey(ecosystem, name string) string {
	eco := normalizeEcosystem(ecosystem)
	if eco == types.EcosystemPyPI {
		name = types.NormalizePyPIName(name)
	}
	return eco + ":" + name
}

// CheckPackage checks a single package for supply chain compromise.
func (d *Detector) CheckPackage(ecosystem, name, version string) *types.SupplyChainFinding {
	db := d.aggregator.getDatabase()

	if db == nil {
		return nil
	}

	pkg, exists := db.Packages[iocKey(ecosystem, name)]
	if !exists {
		return nil
	}

	// Check if this version is compromised
	for _, v := range pkg.Versions {
		if versionMatches(ecosystem, v, version) {
			// Determine finding type based on campaigns
			findingType := "supply_chain_compromise"
			if len(pkg.Campaigns) > 0 {
				findingType = pkg.Campaigns[0] // Use first campaign as type
			}

			return &types.SupplyChainFinding{
				Severity:            "critical",
				Type:                findingType,
				Package:             name,
				InstalledVersion:    version,
				CompromisedVersions: pkg.Versions,
				Action:              "Update immediately and rotate any exposed credentials",
				Campaigns:           pkg.Campaigns,
				AdvisoryIDs:         pkg.AdvisoryIDs,
				Sources:             pkg.Sources,
			}
		}
	}

	return nil
}

// checkNamespace checks if a package is from an at-risk namespace.
// Namespaces (npm scopes) are an npm concept, so this only applies to npm.
func (d *Detector) checkNamespace(ecosystem, name, version string) *types.SupplyChainWarning {
	if normalizeEcosystem(ecosystem) != types.EcosystemNPM {
		return nil
	}

	campaign, ok := lookupNamespaceCampaign(name)
	if !ok {
		return nil
	}

	db := d.aggregator.getDatabase()

	// Only warn if the package isn't already known to be compromised
	if db != nil {
		if pkg, exists := db.Packages[iocKey(ecosystem, name)]; exists {
			for _, v := range pkg.Versions {
				if versionMatches(ecosystem, v, version) {
					return nil // Already reported as finding
				}
			}
		}
	}

	return &types.SupplyChainWarning{
		Type:             "namespace_at_risk",
		Package:          name,
		InstalledVersion: version,
		Namespace:        packageScope(name),
		Campaign:         campaign.Name,
		CampaignWhen:     campaign.When,
		Note:             getNamespaceWarning(name),
	}
}

// CheckDependencies checks a list of dependencies for supply chain issues.
func (d *Detector) CheckDependencies(deps []types.Dependency) ([]types.SupplyChainFinding, []types.SupplyChainWarning) {
	var findings []types.SupplyChainFinding
	var warnings []types.SupplyChainWarning

	for _, dep := range deps {
		// Check for compromised package
		if finding := d.CheckPackage(dep.Ecosystem, dep.Name, dep.Version); finding != nil {
			findings = append(findings, *finding)
			continue
		}

		// Check for at-risk namespace
		if warning := d.checkNamespace(dep.Ecosystem, dep.Name, dep.Version); warning != nil {
			warnings = append(warnings, *warning)
		}
	}

	return findings, warnings
}

// GetStatus returns the current IOC database status.
func (d *Detector) GetStatus() types.IOCDatabaseStatus {
	return d.aggregator.getStatus()
}

// versionMatches checks if a stored version entry matches an installed version.
// Handles exact matches, all-versions wildcards, and (for npm) semver range
// constraints such as "< 1.2.3" or ">= 1.0.0, < 2.0.0":
//   - "1.0.0" matches "1.0.0" (exact)
//   - ">= 0"/"*"/"" matches any version (all versions compromised, common for malware)
//   - "< 1.2.3" matches "1.0.0" but not "1.2.3" (npm only)
//
// PyPI is intentionally excluded from range evaluation: semver is not PEP 440.
func versionMatches(ecosystem, storedVersion, installedVersion string) bool {
	stored := strings.TrimSpace(storedVersion)
	if stored == installedVersion {
		return true
	}
	if stored == ">= 0" || stored == ">=0" || stored == "*" || stored == "" {
		return true // all versions affected (common for typosquat malware)
	}

	// npm: evaluate semver constraints such as "< 1.2.3" or ">= 1.0.0, < 2.0.0".
	// PyPI is intentionally excluded — semver is not PEP 440 (see Honest scope).
	// An unparsable constraint yields no match (ok is false), never a false positive.
	if normalizeEcosystem(ecosystem) == types.EcosystemNPM {
		matched, _ := semverutil.Satisfies(installedVersion, stored)
		return matched
	}
	return false
}
