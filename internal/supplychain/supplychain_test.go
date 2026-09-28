package supplychain

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/undont/supplyscan/internal/types"
)

// mockTestSource implements IOCSource for testing
type mockTestSource struct {
	name     string
	cacheTTL time.Duration
	data     *types.SourceData
}

func (m *mockTestSource) Name() string {
	return m.name
}

func (m *mockTestSource) CacheTTL() time.Duration {
	return m.cacheTTL
}

func (m *mockTestSource) Fetch(_ context.Context, _ *http.Client) (*types.SourceData, error) {
	return m.data, nil
}

// Test helpers
func createTestIOCDatabase() *types.IOCDatabase {
	return &types.IOCDatabase{
		Packages: map[string]types.CompromisedPackage{
			"malicious-pkg": {
				Name:      "malicious-pkg",
				Versions:  []string{"1.0.0", "1.0.1", "1.0.2"},
				Sources:   []string{"test-source"},
				Campaigns: []string{"shai_hulud_v2"},
			},
			"@evil/package": {
				Name:      "@evil/package",
				Versions:  []string{"2.0.0"},
				Sources:   []string{"test-source"},
				Campaigns: []string{"shai_hulud_v2"},
			},
			"@ctrl/tinycolor": {
				Name:      "@ctrl/tinycolor",
				Versions:  []string{"3.4.1"},
				Sources:   []string{"test-source"},
				Campaigns: []string{"shai_hulud_v2"},
			},
		},
		LastUpdated: time.Now().UTC().Format(time.RFC3339),
		Sources:     []string{"test-source"},
	}
}

// createTestDetectorWithDB creates a detector with a pre-loaded database for testing.
func createTestDetectorWithDB(t *testing.T, db *types.IOCDatabase) *Detector {
	t.Helper()

	// Convert IOCDatabase packages to SourceData packages
	sourcePackages := make(map[string]types.SourcePackage)
	for name := range db.Packages {
		pkg := db.Packages[name]
		sourcePackages[name] = types.SourcePackage{
			Name:       pkg.Name,
			Ecosystem:  pkg.Ecosystem,
			Versions:   pkg.Versions,
			AdvisoryID: "",
			Severity:   "critical",
		}
	}

	sourceData := &types.SourceData{
		Source:    "test-source",
		Campaign:  "shai_hulud_v2",
		Packages:  sourcePackages,
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
	}

	mockSource := &mockTestSource{
		name:     "test-source",
		cacheTTL: time.Hour,
		data:     sourceData,
	}

	detector, err := NewDetector(
		withDetectorCacheDir(t.TempDir()),
		withDetectorSources(mockSource),
	)
	if err != nil {
		t.Fatalf("NewDetector() error = %v", err)
	}

	// Load the database
	if err := detector.EnsureLoaded(); err != nil {
		t.Fatalf("EnsureLoaded() error = %v", err)
	}

	return detector
}

// Detector tests
func TestDetector_CheckPackage_Compromised(t *testing.T) {
	detector := createTestDetectorWithDB(t, createTestIOCDatabase())

	tests := []struct {
		name    string
		pkgName string
		version string
		want    bool
	}{
		{"compromised version", "malicious-pkg", "1.0.0", true},
		{"another compromised version", "malicious-pkg", "1.0.1", true},
		{"safe version", "malicious-pkg", "0.9.0", false},
		{"unknown package", "safe-package", "1.0.0", false},
		{"scoped compromised", "@evil/package", "2.0.0", true},
		{"scoped safe version", "@evil/package", "1.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := detector.CheckPackage(types.EcosystemNPM, tt.pkgName, tt.version)
			got := finding != nil
			if got != tt.want {
				t.Errorf("CheckPackage(%q, %q) returned finding = %v, want %v", tt.pkgName, tt.version, got, tt.want)
			}

			if finding != nil {
				if finding.Severity != "critical" {
					t.Errorf("Finding severity = %q, want critical", finding.Severity)
				}
				if finding.Type != "shai_hulud_v2" {
					t.Errorf("Finding type = %q, want shai_hulud_v2", finding.Type)
				}
				if finding.Package != tt.pkgName {
					t.Errorf("Finding package = %q, want %q", finding.Package, tt.pkgName)
				}
			}
		})
	}
}

func TestDetector_CheckPackage_EcosystemScoped(t *testing.T) {
	// Same package name in both registries, compromised at different versions.
	// Matching must be scoped by ecosystem so npm and PyPI don't cross-fire.
	db := &types.IOCDatabase{
		Packages: map[string]types.CompromisedPackage{
			"npm:requests": {
				Name:      "requests",
				Ecosystem: types.EcosystemNPM,
				Versions:  []string{"1.0.0"},
				Campaigns: []string{"shai_hulud_v2"},
			},
			"pypi:requests": {
				Name:      "requests",
				Ecosystem: types.EcosystemPyPI,
				Versions:  []string{"2.0.0"},
				Campaigns: []string{"teampcp"},
			},
		},
		LastUpdated: time.Now().UTC().Format(time.RFC3339),
	}
	detector := createTestDetectorWithDB(t, db)

	tests := []struct {
		name      string
		ecosystem string
		version   string
		want      bool
	}{
		{"npm match", types.EcosystemNPM, "1.0.0", true},
		{"pypi match", types.EcosystemPyPI, "2.0.0", true},
		{"npm version is pypi's compromised version", types.EcosystemNPM, "2.0.0", false},
		{"pypi version is npm's compromised version", types.EcosystemPyPI, "1.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := detector.CheckPackage(tt.ecosystem, "requests", tt.version)
			if (finding != nil) != tt.want {
				t.Errorf("CheckPackage(%q, requests, %q) = %v, want match=%v",
					tt.ecosystem, tt.version, finding, tt.want)
			}
		})
	}
}

func TestDetector_CheckPackage_PyPINameNormalisation(t *testing.T) {
	db := &types.IOCDatabase{
		Packages: map[string]types.CompromisedPackage{
			"pypi:pytorch-lightning": {
				Name:      "pytorch-lightning",
				Ecosystem: types.EcosystemPyPI,
				Versions:  []string{"1.9.0"},
				Campaigns: []string{"teampcp"},
			},
		},
		LastUpdated: time.Now().UTC().Format(time.RFC3339),
	}
	detector := createTestDetectorWithDB(t, db)

	// the lockfile-side name "PyTorch_Lightning" must normalise to match
	if finding := detector.CheckPackage(types.EcosystemPyPI, "PyTorch_Lightning", "1.9.0"); finding == nil {
		t.Error("expected un-normalised PyPI name to match after PEP 503 normalisation")
	}
}

func TestDetector_CheckPackage_NilDatabase(t *testing.T) {
	// Create detector with a source that returns nil data
	emptySource := &mockTestSource{
		name:     "empty",
		cacheTTL: time.Hour,
		data:     nil,
	}

	detector, err := NewDetector(
		withDetectorCacheDir(t.TempDir()),
		withDetectorSources(emptySource),
	)
	if err != nil {
		t.Fatalf("NewDetector() error = %v", err)
	}

	// Don't call EnsureLoaded - database should be nil
	finding := detector.CheckPackage(types.EcosystemNPM, "any-package", "1.0.0")
	if finding != nil {
		t.Error("Expected nil finding when database is nil")
	}
}

func TestDetector_CheckPackageHistory(t *testing.T) {
	detector := createTestDetectorWithDB(t, createTestIOCDatabase())

	tests := []struct {
		name    string
		pkgName string
		version string
		want    bool
	}{
		{"same major compromised", "malicious-pkg", "1.9.0", true},
		{"scoped, same major compromised", "@ctrl/tinycolor", "3.4.0", true},
		{"only other majors compromised", "@evil/package", "1.5.0", false},
		{"zero major, different minor", "malicious-pkg", "0.9.0", false},
		{"same scope, never compromised", "@ctrl/unknown-pkg", "1.0.0", false},
		{"not in database", "lodash", "4.17.21", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning := detector.checkPackageHistory(types.EcosystemNPM, tt.pkgName, tt.version)
			if got := warning != nil; got != tt.want {
				t.Fatalf("checkPackageHistory(%q, %q) returned warning = %v, want %v", tt.pkgName, tt.version, got, tt.want)
			}
			if warning == nil {
				return
			}
			if warning.Type != "other_versions_compromised" {
				t.Errorf("Warning type = %q, want other_versions_compromised", warning.Type)
			}
			if warning.Package != tt.pkgName || warning.InstalledVersion != tt.version {
				t.Errorf("Warning = %s@%s, want %s@%s", warning.Package, warning.InstalledVersion, tt.pkgName, tt.version)
			}
			if len(warning.CompromisedVersions) == 0 {
				t.Error("Warning should list the compromised versions")
			}
		})
	}
}

func TestDetector_CheckDependencies(t *testing.T) {
	detector := createTestDetectorWithDB(t, createTestIOCDatabase())

	deps := []types.Dependency{
		{Name: "malicious-pkg", Version: "1.0.0"},   // Compromised
		{Name: "malicious-pkg", Version: "1.9.0"},   // Safe version of compromised pkg
		{Name: "@ctrl/safe-pkg", Version: "1.0.0"},  // Same scope, never compromised
		{Name: "@ctrl/tinycolor", Version: "3.4.1"}, // Compromised (no warning, just finding)
		{Name: "lodash", Version: "4.17.21"},        // Safe
		{Name: "@babel/core", Version: "7.23.0"},    // Safe
	}

	findings, warnings := detector.CheckDependencies(deps)

	// Should have 2 compromised packages: malicious-pkg@1.0.0 and @ctrl/tinycolor@3.4.1
	if len(findings) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(findings))
	}

	// Should have 1 warning: malicious-pkg@1.9.0 (same major compromised)
	if len(warnings) != 1 {
		t.Errorf("Expected 1 warning, got %d", len(warnings))
	}

	// Verify finding packages
	foundMalicious := false
	foundCtrl := false
	for _, f := range findings {
		if f.Package == "malicious-pkg" && f.InstalledVersion == "1.0.0" {
			foundMalicious = true
		}
		if f.Package == "@ctrl/tinycolor" {
			foundCtrl = true
		}
	}
	if !foundMalicious {
		t.Error("Expected finding for malicious-pkg@1.0.0")
	}
	if !foundCtrl {
		t.Error("Expected finding for @ctrl/tinycolor@3.4.1")
	}

	// Verify warning
	if len(warnings) > 0 && warnings[0].Package != "malicious-pkg" {
		t.Errorf("Warning package = %q, want malicious-pkg", warnings[0].Package)
	}
}

func TestDetector_CheckDependencies_Empty(t *testing.T) {
	detector := createTestDetectorWithDB(t, createTestIOCDatabase())

	findings, warnings := detector.CheckDependencies([]types.Dependency{})

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for empty deps, got %d", len(findings))
	}
	if len(warnings) != 0 {
		t.Errorf("Expected 0 warnings for empty deps, got %d", len(warnings))
	}
}

func TestDetector_GetStatus(t *testing.T) {
	detector := createTestDetectorWithDB(t, createTestIOCDatabase())

	status := detector.GetStatus()

	// Should have loaded the test data
	if status.Packages != 3 {
		t.Errorf("Packages = %d, want 3", status.Packages)
	}

	// Should have sources
	if len(status.Sources) == 0 {
		t.Error("Sources should not be empty")
	}
}

func TestNewDetector_WithCustomSources(t *testing.T) {
	sourceData := &types.SourceData{
		Source:   "custom",
		Campaign: "test-campaign",
		Packages: map[string]types.SourcePackage{
			"test-pkg": {
				Name:     "test-pkg",
				Versions: []string{"1.0.0"},
				Severity: "critical",
			},
		},
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
	}

	customSource := &mockTestSource{
		name:     "custom",
		cacheTTL: time.Hour,
		data:     sourceData,
	}

	detector, err := NewDetector(
		withDetectorCacheDir(t.TempDir()),
		withDetectorSources(customSource),
	)
	if err != nil {
		t.Fatalf("NewDetector() error = %v", err)
	}

	// Load the data
	if err := detector.EnsureLoaded(); err != nil {
		t.Fatalf("EnsureLoaded() error = %v", err)
	}

	// Check package should work
	finding := detector.CheckPackage(types.EcosystemNPM, "test-pkg", "1.0.0")
	if finding == nil {
		t.Error("Expected finding for test-pkg@1.0.0")
	}
}

func TestDetector_Refresh(t *testing.T) {
	sourceData := &types.SourceData{
		Source:   "refreshable",
		Campaign: "test",
		Packages: map[string]types.SourcePackage{
			"pkg": {Name: "pkg", Versions: []string{"1.0.0"}},
		},
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
	}

	testSource := &mockTestSource{
		name:     "refreshable",
		cacheTTL: time.Hour,
		data:     sourceData,
	}

	detector, err := NewDetector(
		withDetectorCacheDir(t.TempDir()),
		withDetectorSources(testSource),
	)
	if err != nil {
		t.Fatalf("NewDetector() error = %v", err)
	}

	// Force refresh
	result, err := detector.Refresh(true)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	if !result.Updated {
		t.Error("Expected Updated = true")
	}

	if result.PackagesCount != 1 {
		t.Errorf("PackagesCount = %d, want 1", result.PackagesCount)
	}
}

func TestVersionMatches(t *testing.T) {
	tests := []struct {
		name             string
		ecosystem        string
		storedVersion    string
		installedVersion string
		want             bool
	}{
		// Exact matches
		{"exact match", types.EcosystemNPM, "1.0.0", "1.0.0", true},
		{"exact mismatch", types.EcosystemNPM, "1.0.0", "2.0.0", false},

		// Wildcard ranges (all versions compromised — common for typosquatting malware)
		{"all versions >= 0", types.EcosystemNPM, ">= 0", "1.2.3", true},
		{"all versions >=0 no space", types.EcosystemNPM, ">=0", "5.0.0", true},
		{"all versions wildcard", types.EcosystemNPM, "*", "3.0.0", true},
		{"empty stored is all versions", types.EcosystemNPM, "", "1.0.0", true},

		// npm semver range evaluation (Feature H)
		{"npm less-than matches below", types.EcosystemNPM, "< 1.2.3", "1.0.0", true},
		{"npm less-than excludes boundary", types.EcosystemNPM, "< 1.2.3", "1.2.3", false},
		{"npm compound AND matches inside", types.EcosystemNPM, ">= 1.0.0, < 2.0.0", "1.5.0", true},
		{"npm compound AND excludes outside", types.EcosystemNPM, ">= 1.0.0, < 2.0.0", "2.5.0", false},
		{"npm gte excludes below", types.EcosystemNPM, ">= 1.0.0", "0.9.0", false},
		{"npm unparsable constraint no match", types.EcosystemNPM, ">=abc", "1.0.0", false},

		// empty ecosystem defaults to npm, so semver ranges are evaluated
		{"empty ecosystem exact match", "", "1.0.0", "1.0.0", true},
		{"empty ecosystem range matches", "", "< 1.2.3", "1.0.0", true},
		{"empty ecosystem range excludes boundary", "", "< 1.2.3", "1.2.3", false},

		// PyPI is exact/wildcard only — semver ranges are NOT evaluated (PEP 440 ≠ semver)
		{"pypi exact match", types.EcosystemPyPI, "1.0.0", "1.0.0", true},
		{"pypi wildcard matches", types.EcosystemPyPI, "*", "2.0.0", true},
		{"pypi range not evaluated", types.EcosystemPyPI, "< 1.2.3", "1.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := versionMatches(tt.ecosystem, tt.storedVersion, tt.installedVersion); got != tt.want {
				t.Errorf("versionMatches(%q, %q, %q) = %v, want %v", tt.ecosystem, tt.storedVersion, tt.installedVersion, got, tt.want)
			}
		})
	}
}

func TestDetector_CheckPackage_WildcardVersion(t *testing.T) {
	// Simulate a typosquatting package where all versions are malware (">= 0")
	db := &types.IOCDatabase{
		Packages: map[string]types.CompromisedPackage{
			"typosquat-pkg": {
				Name:      "typosquat-pkg",
				Versions:  []string{">= 0"}, // All versions
				Sources:   []string{"github"},
				Campaigns: []string{"github-advisory"},
			},
		},
		LastUpdated: time.Now().UTC().Format(time.RFC3339),
		Sources:     []string{"github"},
	}

	detector := createTestDetectorWithDB(t, db)

	// Any version should be flagged
	finding := detector.CheckPackage(types.EcosystemNPM, "typosquat-pkg", "1.0.0")
	if finding == nil {
		t.Error("Expected finding for typosquat-pkg@1.0.0 (all versions compromised)")
	}

	finding2 := detector.CheckPackage(types.EcosystemNPM, "typosquat-pkg", "99.99.99")
	if finding2 == nil {
		t.Error("Expected finding for typosquat-pkg@99.99.99 (all versions compromised)")
	}
}

func TestDetector_EnsureLoaded(t *testing.T) {
	sourceData := &types.SourceData{
		Source:   "loadable",
		Campaign: "test",
		Packages: map[string]types.SourcePackage{
			"loaded-pkg": {Name: "loaded-pkg", Versions: []string{"1.0.0"}},
		},
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
	}

	testSource := &mockTestSource{
		name:     "loadable",
		cacheTTL: time.Hour,
		data:     sourceData,
	}

	detector, err := NewDetector(
		withDetectorCacheDir(t.TempDir()),
		withDetectorSources(testSource),
	)
	if err != nil {
		t.Fatalf("NewDetector() error = %v", err)
	}

	// EnsureLoaded should fetch data
	if err := detector.EnsureLoaded(); err != nil {
		t.Fatalf("EnsureLoaded() error = %v", err)
	}

	// Should be able to check packages now
	finding := detector.CheckPackage(types.EcosystemNPM, "loaded-pkg", "1.0.0")
	if finding == nil {
		t.Error("Expected finding for loaded-pkg@1.0.0")
	}
}
