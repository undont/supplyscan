package supplychain

import (
	"context"
	"net/http"
	"time"

	"github.com/seanhalberthal/supplyscan-mcp/internal/supplychain/sources"
	"github.com/seanhalberthal/supplyscan-mcp/internal/types"
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

	// Default sources: DataDog + GitHub Advisory
	iocSources := cfg.sources
	if len(iocSources) == 0 {
		iocSources = []IOCSource{
			sources.NewDataDogSource(),
			sources.NewGitHubAdvisorySource(),
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

// CheckPackage checks a single package for supply chain compromise.
func (d *Detector) CheckPackage(name, version string) *types.SupplyChainFinding {
	db := d.aggregator.getDatabase()

	if db == nil {
		return nil
	}

	pkg, exists := db.Packages[name]
	if !exists {
		return nil
	}

	// Check if this version is compromised
	for _, v := range pkg.Versions {
		if v == version {
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
func (d *Detector) checkNamespace(name, version string) *types.SupplyChainWarning {
	if !isAtRiskNamespace(name) {
		return nil
	}

	db := d.aggregator.getDatabase()

	// Only warn if the package isn't already known to be compromised
	if db != nil {
		if pkg, exists := db.Packages[name]; exists {
			for _, v := range pkg.Versions {
				if v == version {
					return nil // Already reported as finding
				}
			}
		}
	}

	return &types.SupplyChainWarning{
		Type:             "namespace_at_risk",
		Package:          name,
		InstalledVersion: version,
		Note:             getNamespaceWarning(name),
	}
}

// CheckDependencies checks a list of dependencies for supply chain issues.
func (d *Detector) CheckDependencies(deps []types.Dependency) ([]types.SupplyChainFinding, []types.SupplyChainWarning) {
	var findings []types.SupplyChainFinding
	var warnings []types.SupplyChainWarning

	for _, dep := range deps {
		// Check for compromised package
		if finding := d.CheckPackage(dep.Name, dep.Version); finding != nil {
			findings = append(findings, *finding)
			continue
		}

		// Check for at-risk namespace
		if warning := d.checkNamespace(dep.Name, dep.Version); warning != nil {
			warnings = append(warnings, *warning)
		}
	}

	return findings, warnings
}

// GetStatus returns the current IOC database status.
func (d *Detector) GetStatus() types.IOCDatabaseStatus {
	return d.aggregator.getStatus()
}
