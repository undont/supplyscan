package supplychain

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/seanhalberthal/supplyscan/internal/types"
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

// Namespace tests
func TestIsAtRiskNamespace(t *testing.T) {
	tests := []struct {
		packageName string
		want        bool
	}{
		// At-risk namespaces
		{"@ctrl/tinycolor", true},
		{"@ctrl/another-pkg", true},
		{"@nativescript-community/ui-chart", true},
		{"@crowdstrike/falcon", true},
		{"@asyncapi/spec", true},
		{"@posthog/client", true},
		{"@postman/newman", true},
		{"@ensdomains/resolver", true},
		{"@zapier/core", true},
		{"@art-ws/something", true},
		{"@ngx/forms", true},
		// Safe namespaces
		{"@babel/core", false},
		{"@types/node", false},
		{"@angular/core", false},
		// Non-scoped packages
		{"lodash", false},
		{"express", false},
		// Edge cases
		{"@ctrl", false},    // No slash, invalid package name
		{"ctrl/pkg", false}, // No @ prefix
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.packageName, func(t *testing.T) {
			if got := isAtRiskNamespace(tt.packageName); got != tt.want {
				t.Errorf("IsAtRiskNamespace(%q) = %v, want %v", tt.packageName, got, tt.want)
			}
		})
	}
}

func TestGetNamespaceWarning(t *testing.T) {
	warning := getNamespaceWarning("@ctrl/tinycolor")
	if warning == "" {
		t.Error("GetNamespaceWarning() returned empty string")
	}
	if !strings.Contains(warning, "Shai-Hulud") {
		t.Error("Warning should mention Shai-Hulud campaign")
	}
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
			finding := detector.CheckPackage(tt.pkgName, tt.version)
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
	finding := detector.CheckPackage("any-package", "1.0.0")
	if finding != nil {
		t.Error("Expected nil finding when database is nil")
	}
}

func TestDetector_CheckNamespace(t *testing.T) {
	detector := createTestDetectorWithDB(t, createTestIOCDatabase())

	tests := []struct {
		name    string
		pkgName string
		version string
		want    bool
	}{
		// At-risk namespace, safe version - should warn
		{"at-risk safe version", "@ctrl/unknown-pkg", "1.0.0", true},
		{"at-risk another", "@posthog/analytics", "2.0.0", true},
		// At-risk namespace, compromised version - should NOT warn (it's a finding, not warning)
		{"at-risk compromised", "@ctrl/tinycolor", "3.4.1", false},
		// Safe namespace - no warning
		{"safe namespace", "@babel/core", "7.0.0", false},
		// Non-scoped - no warning
		{"non-scoped", "lodash", "4.17.21", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning := detector.checkNamespace(tt.pkgName, tt.version)
			got := warning != nil
			if got != tt.want {
				t.Errorf("CheckNamespace(%q, %q) returned warning = %v, want %v", tt.pkgName, tt.version, got, tt.want)
			}

			if warning != nil {
				if warning.Type != "namespace_at_risk" {
					t.Errorf("Warning type = %q, want namespace_at_risk", warning.Type)
				}
				if warning.Package != tt.pkgName {
					t.Errorf("Warning package = %q, want %q", warning.Package, tt.pkgName)
				}
			}
		})
	}
}

func TestDetector_CheckDependencies(t *testing.T) {
	detector := createTestDetectorWithDB(t, createTestIOCDatabase())

	deps := []types.Dependency{
		{Name: "malicious-pkg", Version: "1.0.0"},   // Compromised
		{Name: "malicious-pkg", Version: "0.9.0"},   // Safe version of compromised pkg
		{Name: "@ctrl/safe-pkg", Version: "1.0.0"},  // At-risk namespace
		{Name: "@ctrl/tinycolor", Version: "3.4.1"}, // Compromised (no warning, just finding)
		{Name: "lodash", Version: "4.17.21"},        // Safe
		{Name: "@babel/core", Version: "7.23.0"},    // Safe
	}

	findings, warnings := detector.CheckDependencies(deps)

	// Should have 2 compromised packages: malicious-pkg@1.0.0 and @ctrl/tinycolor@3.4.1
	if len(findings) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(findings))
	}

	// Should have 1 warning: @ctrl/safe-pkg (at-risk namespace, not compromised)
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
	if len(warnings) > 0 && warnings[0].Package != "@ctrl/safe-pkg" {
		t.Errorf("Warning package = %q, want @ctrl/safe-pkg", warnings[0].Package)
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

func TestAtRiskNamespaces_Coverage(t *testing.T) {
	// Verify all defined namespaces are actually checked
	for _, ns := range atRiskNamespaces {
		testPkg := ns + "/test-package"
		if !isAtRiskNamespace(testPkg) {
			t.Errorf("IsAtRiskNamespace(%q) = false, namespace %q should be at-risk", testPkg, ns)
		}
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
	finding := detector.CheckPackage("test-pkg", "1.0.0")
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
	finding := detector.CheckPackage("loaded-pkg", "1.0.0")
	if finding == nil {
		t.Error("Expected finding for loaded-pkg@1.0.0")
	}
}
