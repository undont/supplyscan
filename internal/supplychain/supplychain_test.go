package supplychain

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/seanhalberthal/supplyscan-mcp/internal/types"
)

// Test helpers
func createTestIOCDatabase() *types.IOCDatabase {
	return &types.IOCDatabase{
		Packages: map[string]types.CompromisedPackage{
			"malicious-pkg": {
				Name:     "malicious-pkg",
				Versions: []string{"1.0.0", "1.0.1", "1.0.2"},
				Sources:  []string{"datadog"},
				Campaign: "shai-hulud-v2",
			},
			"@evil/package": {
				Name:     "@evil/package",
				Versions: []string{"2.0.0"},
				Sources:  []string{"datadog"},
				Campaign: "shai-hulud-v2",
			},
			"@ctrl/tinycolor": {
				Name:     "@ctrl/tinycolor",
				Versions: []string{"3.4.1"},
				Sources:  []string{"datadog"},
				Campaign: "shai-hulud-v2",
			},
		},
		LastUpdated: time.Now().UTC().Format(time.RFC3339),
		Sources:     []string{"datadog"},
	}
}

func setupTestCache(t *testing.T) (*IOCCache, string) {
	t.Helper()
	tmpDir := t.TempDir()

	cache := &IOCCache{cacheDir: tmpDir}
	return cache, tmpDir
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
		{"@ctrl", false},  // No slash, invalid package name
		{"ctrl/pkg", false}, // No @ prefix
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.packageName, func(t *testing.T) {
			if got := IsAtRiskNamespace(tt.packageName); got != tt.want {
				t.Errorf("IsAtRiskNamespace(%q) = %v, want %v", tt.packageName, got, tt.want)
			}
		})
	}
}

func TestGetNamespaceWarning(t *testing.T) {
	warning := GetNamespaceWarning("@ctrl/tinycolor")
	if warning == "" {
		t.Error("GetNamespaceWarning() returned empty string")
	}
	if !strings.Contains(warning, "Shai-Hulud") {
		t.Error("Warning should mention Shai-Hulud campaign")
	}
}

// Detector tests
func TestDetector_CheckPackage_Compromised(t *testing.T) {
	detector := &Detector{
		db: createTestIOCDatabase(),
	}

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
	detector := &Detector{db: nil}

	finding := detector.CheckPackage("any-package", "1.0.0")
	if finding != nil {
		t.Error("Expected nil finding when database is nil")
	}
}

func TestDetector_CheckNamespace(t *testing.T) {
	detector := &Detector{
		db: createTestIOCDatabase(),
	}

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
			warning := detector.CheckNamespace(tt.pkgName, tt.version)
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
	detector := &Detector{
		db: createTestIOCDatabase(),
	}

	deps := []types.Dependency{
		{Name: "malicious-pkg", Version: "1.0.0"},     // Compromised
		{Name: "malicious-pkg", Version: "0.9.0"},     // Safe version of compromised pkg
		{Name: "@ctrl/safe-pkg", Version: "1.0.0"},    // At-risk namespace
		{Name: "@ctrl/tinycolor", Version: "3.4.1"},   // Compromised (no warning, just finding)
		{Name: "lodash", Version: "4.17.21"},          // Safe
		{Name: "@babel/core", Version: "7.23.0"},      // Safe
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
	detector := &Detector{
		db: createTestIOCDatabase(),
	}

	findings, warnings := detector.CheckDependencies([]types.Dependency{})

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for empty deps, got %d", len(findings))
	}
	if len(warnings) != 0 {
		t.Errorf("Expected 0 warnings for empty deps, got %d", len(warnings))
	}
}

func TestDetector_GetStatus_NoCache(t *testing.T) {
	cache, _ := setupTestCache(t)
	detector := &Detector{cache: cache}

	status := detector.GetStatus()

	if status.Packages != 0 {
		t.Errorf("Packages = %d, want 0", status.Packages)
	}
	if status.LastUpdated != "not loaded" {
		t.Errorf("LastUpdated = %q, want 'not loaded'", status.LastUpdated)
	}
}

func TestDetector_GetStatus_WithCache(t *testing.T) {
	cache, tmpDir := setupTestCache(t)

	// Create meta file
	meta := &types.IOCMeta{
		LastUpdated:  time.Now().UTC().Format(time.RFC3339),
		PackageCount: 42,
		VersionCount: 100,
	}
	metaData, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(filepath.Join(tmpDir, "meta.json"), metaData, 0600); err != nil {
		t.Fatal(err)
	}

	detector := &Detector{cache: cache}
	status := detector.GetStatus()

	if status.Packages != 42 {
		t.Errorf("Packages = %d, want 42", status.Packages)
	}
	if status.Versions != 100 {
		t.Errorf("Versions = %d, want 100", status.Versions)
	}
}

// IOC Cache tests
func TestIOCCache_SaveAndLoad(t *testing.T) {
	cache, _ := setupTestCache(t)
	db := createTestIOCDatabase()

	// Save
	if err := cache.Save(db); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Load
	loaded, err := cache.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if loaded == nil {
		t.Fatal("Load() returned nil")
	}

	if len(loaded.Packages) != len(db.Packages) {
		t.Errorf("Loaded packages = %d, want %d", len(loaded.Packages), len(db.Packages))
	}

	// Check specific package
	if pkg, ok := loaded.Packages["malicious-pkg"]; !ok {
		t.Error("Expected malicious-pkg in loaded database")
	} else {
		if len(pkg.Versions) != 3 {
			t.Errorf("malicious-pkg versions = %d, want 3", len(pkg.Versions))
		}
	}
}

func TestIOCCache_LoadNonexistent(t *testing.T) {
	cache, _ := setupTestCache(t)

	loaded, err := cache.Load()
	if err != nil {
		t.Fatalf("Load() error = %v (expected nil, nil for nonexistent)", err)
	}
	if loaded != nil {
		t.Error("Load() should return nil for nonexistent cache")
	}
}

func TestIOCCache_SaveAndLoadMeta(t *testing.T) {
	cache, _ := setupTestCache(t)

	meta := &types.IOCMeta{
		LastUpdated:  time.Now().UTC().Format(time.RFC3339),
		ETag:         "abc123",
		PackageCount: 50,
		VersionCount: 150,
	}

	// Save
	if err := cache.SaveMeta(meta); err != nil {
		t.Fatalf("SaveMeta() error = %v", err)
	}

	// Load
	loaded, err := cache.LoadMeta()
	if err != nil {
		t.Fatalf("LoadMeta() error = %v", err)
	}

	if loaded == nil {
		t.Fatal("LoadMeta() returned nil")
	}

	if loaded.PackageCount != 50 {
		t.Errorf("PackageCount = %d, want 50", loaded.PackageCount)
	}
	if loaded.VersionCount != 150 {
		t.Errorf("VersionCount = %d, want 150", loaded.VersionCount)
	}
	if loaded.ETag != "abc123" {
		t.Errorf("ETag = %q, want abc123", loaded.ETag)
	}
}

func TestIOCCache_IsStale(t *testing.T) {
	cache, tmpDir := setupTestCache(t)

	// No meta file - should be stale
	if !cache.IsStale() {
		t.Error("IsStale() should return true when no meta file exists")
	}

	// Recent meta - should not be stale
	meta := &types.IOCMeta{
		LastUpdated: time.Now().UTC().Format(time.RFC3339),
	}
	metaData, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(filepath.Join(tmpDir, "meta.json"), metaData, 0600); err != nil {
		t.Fatal(err)
	}

	if cache.IsStale() {
		t.Error("IsStale() should return false for recent cache")
	}

	// Old meta - should be stale
	oldMeta := &types.IOCMeta{
		LastUpdated: time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339),
	}
	oldMetaData, _ := json.MarshalIndent(oldMeta, "", "  ")
	if err := os.WriteFile(filepath.Join(tmpDir, "meta.json"), oldMetaData, 0600); err != nil {
		t.Fatal(err)
	}

	if !cache.IsStale() {
		t.Error("IsStale() should return true for old cache (>6 hours)")
	}
}

func TestIOCCache_CacheAgeHours(t *testing.T) {
	cache, tmpDir := setupTestCache(t)

	// No meta file
	if age := cache.CacheAgeHours(); age != -1 {
		t.Errorf("CacheAgeHours() = %d, want -1 for no meta", age)
	}

	// Create meta with known time
	pastTime := time.Now().Add(-3 * time.Hour)
	meta := &types.IOCMeta{
		LastUpdated: pastTime.UTC().Format(time.RFC3339),
	}
	metaData, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(filepath.Join(tmpDir, "meta.json"), metaData, 0600); err != nil {
		t.Fatal(err)
	}

	age := cache.CacheAgeHours()
	// Allow some tolerance for test execution time
	if age < 2 || age > 4 {
		t.Errorf("CacheAgeHours() = %d, expected ~3", age)
	}
}

// CSV parsing tests
func TestParseIOCCSV(t *testing.T) {
	csvData := `package_name,package_versions,sources
malicious-pkg,"1.0.0,1.0.1",datadog
@evil/scoped,"2.0.0,2.0.1","datadog,other"
single-version,3.0.0,datadog
`

	db, err := parseIOCCSV(strings.NewReader(csvData))
	if err != nil {
		t.Fatalf("parseIOCCSV() error = %v", err)
	}

	if len(db.Packages) != 3 {
		t.Errorf("Packages count = %d, want 3", len(db.Packages))
	}

	// Check malicious-pkg
	if pkg, ok := db.Packages["malicious-pkg"]; !ok {
		t.Error("Expected malicious-pkg in database")
	} else {
		if len(pkg.Versions) != 2 {
			t.Errorf("malicious-pkg versions = %d, want 2", len(pkg.Versions))
		}
	}

	// Check scoped package
	if pkg, ok := db.Packages["@evil/scoped"]; !ok {
		t.Error("Expected @evil/scoped in database")
	} else {
		if len(pkg.Versions) != 2 {
			t.Errorf("@evil/scoped versions = %d, want 2", len(pkg.Versions))
		}
		if len(pkg.Sources) != 2 {
			t.Errorf("@evil/scoped sources = %d, want 2", len(pkg.Sources))
		}
	}
}

func TestParseIOCCSV_AlternativeHeaders(t *testing.T) {
	// Test with alternative column names
	csvData := `name,version,reporter
alt-pkg,1.0.0,security-team
`

	db, err := parseIOCCSV(strings.NewReader(csvData))
	if err != nil {
		t.Fatalf("parseIOCCSV() error = %v", err)
	}

	if _, ok := db.Packages["alt-pkg"]; !ok {
		t.Error("Expected alt-pkg in database with alternative headers")
	}
}

func TestParseIOCCSV_InvalidHeader(t *testing.T) {
	csvData := `invalid_col1,invalid_col2
data1,data2
`

	_, err := parseIOCCSV(strings.NewReader(csvData))
	if err == nil {
		t.Error("Expected error for CSV with invalid headers")
	}
}

func TestParseIOCCSV_Empty(t *testing.T) {
	csvData := `package_name,package_versions,sources
`

	db, err := parseIOCCSV(strings.NewReader(csvData))
	if err != nil {
		t.Fatalf("parseIOCCSV() error = %v", err)
	}

	if len(db.Packages) != 0 {
		t.Errorf("Expected empty database, got %d packages", len(db.Packages))
	}
}

func TestParseIOCCSV_MalformedRow(t *testing.T) {
	csvData := `package_name,package_versions,sources
valid-pkg,1.0.0,datadog
invalid
another-valid,2.0.0,datadog
`

	db, err := parseIOCCSV(strings.NewReader(csvData))
	if err != nil {
		t.Fatalf("parseIOCCSV() error = %v", err)
	}

	// Should have 2 valid packages (malformed row skipped)
	if len(db.Packages) != 2 {
		t.Errorf("Expected 2 packages (malformed skipped), got %d", len(db.Packages))
	}
}

func TestFindColumnIndex(t *testing.T) {
	header := []string{"Name", "Version", "Source"}

	tests := []struct {
		names []string
		want  int
	}{
		{[]string{"name"}, 0},
		{[]string{"version"}, 1},
		{[]string{"SOURCE"}, 2}, // Case insensitive
		{[]string{"missing"}, -1},
		{[]string{"unknown", "name"}, 0}, // Multiple possible names
	}

	for _, tt := range tests {
		t.Run(strings.Join(tt.names, "|"), func(t *testing.T) {
			if got := findColumnIndex(header, tt.names...); got != tt.want {
				t.Errorf("findColumnIndex() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSplitAndTrim(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"a,b,c", 3},
		{"a, b, c", 3},
		{"  a  ,  b  ,  c  ", 3},
		{"single", 1},
		{"", 0},
		{",,,", 0}, // All empty after trim
		{"a,,b", 2}, // Empty middle
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := splitAndTrim(tt.input)
			if len(result) != tt.want {
				t.Errorf("splitAndTrim(%q) = %v (len %d), want len %d", tt.input, result, len(result), tt.want)
			}
		})
	}
}

// Integration test
func TestDetector_EnsureLoaded_WithCache(t *testing.T) {
	cache, tmpDir := setupTestCache(t)
	db := createTestIOCDatabase()

	// Save cache and meta
	if err := cache.Save(db); err != nil {
		t.Fatal(err)
	}

	meta := &types.IOCMeta{
		LastUpdated:  time.Now().UTC().Format(time.RFC3339),
		PackageCount: len(db.Packages),
		VersionCount: 6,
	}
	if err := cache.SaveMeta(meta); err != nil {
		t.Fatal(err)
	}

	// Create detector with this cache
	detector := &Detector{
		cache: &IOCCache{cacheDir: tmpDir},
	}

	// EnsureLoaded should load from cache
	if err := detector.EnsureLoaded(); err != nil {
		t.Fatalf("EnsureLoaded() error = %v", err)
	}

	if detector.db == nil {
		t.Fatal("EnsureLoaded() did not load database")
	}

	// Should be able to check packages now
	finding := detector.CheckPackage("malicious-pkg", "1.0.0")
	if finding == nil {
		t.Error("Expected finding for malicious-pkg@1.0.0 after EnsureLoaded")
	}
}

func TestAtRiskNamespaces_Coverage(t *testing.T) {
	// Verify all defined namespaces are actually checked
	for _, ns := range AtRiskNamespaces {
		testPkg := ns + "/test-package"
		if !IsAtRiskNamespace(testPkg) {
			t.Errorf("IsAtRiskNamespace(%q) = false, namespace %q should be at-risk", testPkg, ns)
		}
	}
}
