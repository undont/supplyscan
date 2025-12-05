package supplychain

import (
	"github.com/seanhalberthal/supplyscan-mcp/internal/types"
)

// Detector checks packages against the IOC database.
type Detector struct {
	cache *IOCCache
	db    *types.IOCDatabase
}

// NewDetector creates a new supply chain detector.
func NewDetector() (*Detector, error) {
	cache, err := NewIOCCache()
	if err != nil {
		return nil, err
	}

	return &Detector{cache: cache}, nil
}

// EnsureLoaded loads the IOC database, refreshing if needed.
func (d *Detector) EnsureLoaded() error {
	if d.db != nil {
		return nil
	}

	// Try to load from cache
	db, err := d.cache.Load()
	if err != nil {
		return err
	}

	if db == nil || d.cache.IsStale() {
		// Refresh the cache
		_, err := d.cache.Refresh(false)
		if err != nil {
			// If refresh fails but we have stale data, use it
			if db != nil {
				d.db = db
				return nil
			}
			return err
		}

		// Reload after refresh
		db, err = d.cache.Load()
		if err != nil {
			return err
		}
	}

	d.db = db
	return nil
}

// Refresh forces a refresh of the IOC database.
func (d *Detector) Refresh(force bool) (*types.RefreshResult, error) {
	result, err := d.cache.Refresh(force)
	if err != nil {
		return nil, err
	}

	// Reload database after refresh
	d.db, _ = d.cache.Load()
	return result, nil
}

// CheckPackage checks a single package for supply chain compromise.
func (d *Detector) CheckPackage(name, version string) *types.SupplyChainFinding {
	if d.db == nil {
		return nil
	}

	pkg, exists := d.db.Packages[name]
	if !exists {
		return nil
	}

	// Check if this version is compromised
	for _, v := range pkg.Versions {
		if v == version {
			return &types.SupplyChainFinding{
				Severity:            "critical",
				Type:                "shai_hulud_v2",
				Package:             name,
				InstalledVersion:    version,
				CompromisedVersions: pkg.Versions,
				Action:              "Update immediately and rotate any exposed credentials",
			}
		}
	}

	return nil
}

// CheckNamespace checks if a package is from an at-risk namespace.
func (d *Detector) CheckNamespace(name, version string) *types.SupplyChainWarning {
	if !IsAtRiskNamespace(name) {
		return nil
	}

	// Only warn if the package isn't already known to be compromised
	if d.db != nil {
		if pkg, exists := d.db.Packages[name]; exists {
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
		Note:             GetNamespaceWarning(name),
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
		if warning := d.CheckNamespace(dep.Name, dep.Version); warning != nil {
			warnings = append(warnings, *warning)
		}
	}

	return findings, warnings
}

// GetStatus returns the current IOC database status.
func (d *Detector) GetStatus() types.IOCDatabaseStatus {
	meta, _ := d.cache.LoadMeta()
	if meta == nil {
		return types.IOCDatabaseStatus{
			Packages:    0,
			Versions:    0,
			LastUpdated: "not loaded",
			Sources:     []string{},
		}
	}

	sources := []string{"datadog"}
	if d.db != nil {
		sources = d.db.Sources
	}

	return types.IOCDatabaseStatus{
		Packages:    meta.PackageCount,
		Versions:    meta.VersionCount,
		LastUpdated: meta.LastUpdated,
		Sources:     sources,
	}
}