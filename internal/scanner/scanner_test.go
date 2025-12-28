package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/seanhalberthal/supplyscan/internal/types"
)

// Helper to create test fixtures
func createTestProject(t *testing.T, lockfiles map[string]string) string {
	t.Helper()
	tmpDir := t.TempDir()

	for name, content := range lockfiles {
		path := filepath.Join(tmpDir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	return tmpDir
}

func TestScanOptions_Defaults(t *testing.T) {
	opts := ScanOptions{}

	if opts.Path != "" {
		t.Errorf("Default Path = %q, want empty", opts.Path)
	}
	if opts.Recursive {
		t.Error("Default Recursive = true, want false")
	}
	if opts.IncludeDev {
		t.Error("Default IncludeDev = true, want false")
	}
}

func TestFilterNonDev(t *testing.T) {
	deps := []types.Dependency{
		{Name: "prod1", Version: "1.0.0", Dev: false},
		{Name: "dev1", Version: "1.0.0", Dev: true},
		{Name: "prod2", Version: "1.0.0", Dev: false},
		{Name: "dev2", Version: "1.0.0", Dev: true},
	}

	filtered := filterNonDev(deps)

	if len(filtered) != 2 {
		t.Errorf("filterNonDev() returned %d deps, want 2", len(filtered))
	}

	for _, dep := range filtered {
		if dep.Dev {
			t.Errorf("filterNonDev() included dev dependency: %s", dep.Name)
		}
	}
}

func TestFilterNonDev_AllDev(t *testing.T) {
	deps := []types.Dependency{
		{Name: "dev1", Version: "1.0.0", Dev: true},
		{Name: "dev2", Version: "1.0.0", Dev: true},
	}

	filtered := filterNonDev(deps)

	if len(filtered) != 0 {
		t.Errorf("filterNonDev() returned %d deps, want 0", len(filtered))
	}
}

func TestFilterNonDev_Empty(t *testing.T) {
	filtered := filterNonDev([]types.Dependency{})

	if filtered == nil {
		t.Error("filterNonDev() returned nil, want empty slice")
	}
	if len(filtered) != 0 {
		t.Errorf("filterNonDev() returned %d deps, want 0", len(filtered))
	}
}

func TestCountIssues(t *testing.T) {
	result := &types.ScanResult{
		SupplyChain: types.SupplyChainResult{
			Findings: []types.SupplyChainFinding{
				{Severity: "critical", Package: "bad-pkg"},
				{Severity: "critical", Package: "bad-pkg2"},
			},
		},
		Vulnerabilities: types.VulnerabilityResult{
			Findings: []types.VulnerabilityFinding{
				{Severity: "critical", Package: "crit-pkg"},
				{Severity: "high", Package: "high-pkg1"},
				{Severity: "high", Package: "high-pkg2"},
				{Severity: "moderate", Package: "mod-pkg"},
				{Severity: "low", Package: "low-pkg"},   // Not counted
				{Severity: "info", Package: "info-pkg"}, // Not counted
			},
		},
	}

	counts := countIssues(result)

	if counts.SupplyChain != 2 {
		t.Errorf("SupplyChain = %d, want 2", counts.SupplyChain)
	}
	if counts.Critical != 1 {
		t.Errorf("Critical = %d, want 1", counts.Critical)
	}
	if counts.High != 2 {
		t.Errorf("High = %d, want 2", counts.High)
	}
	if counts.Moderate != 1 {
		t.Errorf("Moderate = %d, want 1", counts.Moderate)
	}
}

func TestCountIssues_Empty(t *testing.T) {
	result := &types.ScanResult{
		SupplyChain: types.SupplyChainResult{
			Findings: []types.SupplyChainFinding{},
		},
		Vulnerabilities: types.VulnerabilityResult{
			Findings: []types.VulnerabilityFinding{},
		},
	}

	counts := countIssues(result)

	if counts.SupplyChain != 0 {
		t.Errorf("SupplyChain = %d, want 0", counts.SupplyChain)
	}
	if counts.Critical != 0 {
		t.Errorf("Critical = %d, want 0", counts.Critical)
	}
	if counts.High != 0 {
		t.Errorf("High = %d, want 0", counts.High)
	}
	if counts.Moderate != 0 {
		t.Errorf("Moderate = %d, want 0", counts.Moderate)
	}
}

func TestScan_SingleLockfile(t *testing.T) {
	lockfileContent := `{
		"name": "test",
		"version": "1.0.0",
		"lockfileVersion": 3,
		"packages": {
			"node_modules/lodash": {
				"version": "4.17.21"
			},
			"node_modules/express": {
				"version": "4.18.2"
			},
			"node_modules/jest": {
				"version": "29.7.0",
				"dev": true
			}
		}
	}`

	projectDir := createTestProject(t, map[string]string{
		"package-lock.json": lockfileContent,
	})

	scanner, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	result, err := scanner.Scan(ScanOptions{
		Path:       projectDir,
		Recursive:  false,
		IncludeDev: true,
	})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	// Verify summary
	if result.Summary.LockfilesScanned != 1 {
		t.Errorf("LockfilesScanned = %d, want 1", result.Summary.LockfilesScanned)
	}
	if result.Summary.TotalDependencies != 3 {
		t.Errorf("TotalDependencies = %d, want 3", result.Summary.TotalDependencies)
	}

	// Verify lockfiles list
	if len(result.Lockfiles) != 1 {
		t.Errorf("Lockfiles count = %d, want 1", len(result.Lockfiles))
	} else if result.Lockfiles[0].Type != "npm" {
		t.Errorf("Lockfile type = %q, want npm", result.Lockfiles[0].Type)
	}

	// Verify arrays are not nil
	if result.SupplyChain.Findings == nil {
		t.Error("SupplyChain.Findings is nil")
	}
	if result.SupplyChain.Warnings == nil {
		t.Error("SupplyChain.Warnings is nil")
	}
	if result.Vulnerabilities.Findings == nil {
		t.Error("Vulnerabilities.Findings is nil")
	}
}

func TestScan_ExcludeDevDependencies(t *testing.T) {
	lockfileContent := `{
		"name": "test",
		"version": "1.0.0",
		"lockfileVersion": 3,
		"packages": {
			"node_modules/prod-pkg": {
				"version": "1.0.0"
			},
			"node_modules/dev-pkg": {
				"version": "1.0.0",
				"dev": true
			}
		}
	}`

	projectDir := createTestProject(t, map[string]string{
		"package-lock.json": lockfileContent,
	})

	scanner, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// With dev deps excluded
	result, err := scanner.Scan(ScanOptions{
		Path:       projectDir,
		Recursive:  false,
		IncludeDev: false,
	})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	// Only prod-pkg should be counted
	if result.Summary.TotalDependencies != 1 {
		t.Errorf("TotalDependencies (no dev) = %d, want 1", result.Summary.TotalDependencies)
	}

	// With dev deps included
	result2, err := scanner.Scan(ScanOptions{
		Path:       projectDir,
		Recursive:  false,
		IncludeDev: true,
	})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	// Both should be counted
	if result2.Summary.TotalDependencies != 2 {
		t.Errorf("TotalDependencies (with dev) = %d, want 2", result2.Summary.TotalDependencies)
	}
}

func TestScan_RecursiveSearch(t *testing.T) {
	projectDir := createTestProject(t, map[string]string{
		"package-lock.json": `{
			"name": "root",
			"lockfileVersion": 3,
			"packages": {"node_modules/a": {"version": "1.0.0"}}
		}`,
		"packages/frontend/package-lock.json": `{
			"name": "frontend",
			"lockfileVersion": 3,
			"packages": {"node_modules/b": {"version": "1.0.0"}}
		}`,
		"packages/backend/package-lock.json": `{
			"name": "backend",
			"lockfileVersion": 3,
			"packages": {"node_modules/c": {"version": "1.0.0"}}
		}`,
	})

	scanner, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Non-recursive
	result1, err := scanner.Scan(ScanOptions{
		Path:      projectDir,
		Recursive: false,
	})
	if err != nil {
		t.Fatalf("Scan() non-recursive error = %v", err)
	}

	if result1.Summary.LockfilesScanned != 1 {
		t.Errorf("Non-recursive scan found %d lockfiles, want 1", result1.Summary.LockfilesScanned)
	}

	// Recursive
	result2, err := scanner.Scan(ScanOptions{
		Path:      projectDir,
		Recursive: true,
	})
	if err != nil {
		t.Fatalf("Scan() recursive error = %v", err)
	}

	if result2.Summary.LockfilesScanned != 3 {
		t.Errorf("Recursive scan found %d lockfiles, want 3", result2.Summary.LockfilesScanned)
	}
}

func TestScan_NoLockfiles(t *testing.T) {
	projectDir := t.TempDir()

	scanner, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	result, err := scanner.Scan(ScanOptions{
		Path: projectDir,
	})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if result.Summary.LockfilesScanned != 0 {
		t.Errorf("LockfilesScanned = %d, want 0", result.Summary.LockfilesScanned)
	}
	if result.Summary.TotalDependencies != 0 {
		t.Errorf("TotalDependencies = %d, want 0", result.Summary.TotalDependencies)
	}
}

func TestScan_InvalidPath(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = scanner.Scan(ScanOptions{
		Path: "/nonexistent/path/that/does/not/exist",
	})
	if err == nil {
		t.Error("Expected error for invalid path")
	}
}

func TestScan_SkipsMalformedLockfiles(t *testing.T) {
	projectDir := createTestProject(t, map[string]string{
		"package-lock.json": `{invalid json`,
		"sub/package-lock.json": `{
			"name": "valid",
			"lockfileVersion": 3,
			"packages": {"node_modules/pkg": {"version": "1.0.0"}}
		}`,
	})

	scanner, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	result, err := scanner.Scan(ScanOptions{
		Path:      projectDir,
		Recursive: true,
	})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	// Should have scanned 1 valid lockfile (malformed skipped)
	if result.Summary.LockfilesScanned != 1 {
		t.Errorf("LockfilesScanned = %d, want 1 (malformed should be skipped)", result.Summary.LockfilesScanned)
	}
}

func TestScan_MultipleLockfileTypes(t *testing.T) {
	projectDir := createTestProject(t, map[string]string{
		"npm-project/package-lock.json": `{
			"name": "npm-test",
			"lockfileVersion": 3,
			"packages": {"node_modules/a": {"version": "1.0.0"}}
		}`,
		"yarn-project/yarn.lock": `# yarn lockfile v1

lodash@^4.17.0:
  version "4.17.21"
`,
		"pnpm-project/pnpm-lock.yaml": `lockfileVersion: '9.0'
packages:
  express@4.18.2:
    resolution: {integrity: sha512-...}
`,
	})

	scanner, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	result, err := scanner.Scan(ScanOptions{
		Path:      projectDir,
		Recursive: true,
	})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if result.Summary.LockfilesScanned != 3 {
		t.Errorf("LockfilesScanned = %d, want 3", result.Summary.LockfilesScanned)
	}

	// Check lockfile types
	typeMap := make(map[string]bool)
	for _, lf := range result.Lockfiles {
		typeMap[lf.Type] = true
	}

	expectedTypes := []string{"npm", "yarn-classic", "pnpm"}
	for _, et := range expectedTypes {
		if !typeMap[et] {
			t.Errorf("Expected lockfile type %q not found", et)
		}
	}
}

func TestCheckPackage(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Test with a known safe package (this won't check real vulnerabilities in tests)
	result, err := scanner.CheckPackage("lodash", "4.17.21")
	if err != nil {
		t.Fatalf("CheckPackage() error = %v", err)
	}

	// Should return a valid result structure
	if result == nil {
		t.Fatal("CheckPackage() returned nil result")
	}

	// Vulnerabilities array should not be nil
	if result.Vulnerabilities == nil {
		t.Error("Vulnerabilities is nil")
	}
}

func TestGetStatus(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	status := scanner.GetStatus()

	// Should return valid status even without cached IOCs
	if status.Sources == nil {
		t.Error("Sources is nil")
	}
}

func TestNew_CreatesDetectorAndClient(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if scanner.detector == nil {
		t.Error("detector is nil")
	}
	if scanner.auditClient == nil {
		t.Error("auditClient is nil")
	}
}

func TestScanResult_JSONMarshaling(t *testing.T) {
	result := &types.ScanResult{
		Summary: types.ScanSummary{
			LockfilesScanned:  2,
			TotalDependencies: 50,
			Issues: types.IssueCounts{
				Critical:    1,
				High:        2,
				Moderate:    3,
				SupplyChain: 1,
			},
		},
		SupplyChain: types.SupplyChainResult{
			Findings: []types.SupplyChainFinding{
				{
					Severity: "critical",
					Type:     "shai_hulud_v2",
					Package:  "bad-pkg",
				},
			},
			Warnings: []types.SupplyChainWarning{},
		},
		Vulnerabilities: types.VulnerabilityResult{
			Findings: []types.VulnerabilityFinding{},
		},
		Lockfiles: []types.LockfileInfo{
			{Path: "/test/package-lock.json", Type: "npm", Dependencies: 50},
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var parsed types.ScanResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if parsed.Summary.LockfilesScanned != 2 {
		t.Errorf("LockfilesScanned = %d, want 2", parsed.Summary.LockfilesScanned)
	}
	if len(parsed.SupplyChain.Findings) != 1 {
		t.Errorf("SupplyChain.Findings = %d, want 1", len(parsed.SupplyChain.Findings))
	}
}

func TestScan_SetsLockfilePath(t *testing.T) {
	projectDir := createTestProject(t, map[string]string{
		"package-lock.json": `{
			"name": "test",
			"lockfileVersion": 3,
			"packages": {"node_modules/pkg": {"version": "1.0.0"}}
		}`,
	})

	scanner, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	result, err := scanner.Scan(ScanOptions{Path: projectDir})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if len(result.Lockfiles) != 1 {
		t.Fatalf("Expected 1 lockfile, got %d", len(result.Lockfiles))
	}

	lockfilePath := result.Lockfiles[0].Path
	if lockfilePath == "" {
		t.Error("Lockfile path is empty")
	}
	if filepath.Base(lockfilePath) != "package-lock.json" {
		t.Errorf("Lockfile basename = %q, want package-lock.json", filepath.Base(lockfilePath))
	}
}

func BenchmarkScan(b *testing.B) {
	// Create a larger test project
	lockfileContent := `{
		"name": "bench-test",
		"lockfileVersion": 3,
		"packages": {`

	for i := 0; i < 100; i++ {
		if i > 0 {
			lockfileContent += ","
		}
		lockfileContent += `
			"node_modules/pkg` + string(rune('a'+i%26)) + `": {"version": "1.0.0"}`
	}
	lockfileContent += `
		}
	}`

	tmpDir, _ := os.MkdirTemp("", "bench-scan-*")
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			panic(err)
		}
	}(tmpDir)

	err := os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte(lockfileContent), 0644)
	if err != nil {
		fmt.Printf("Error writing lockfile: %v\n", err)
	}

	scanner, _ := New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := scanner.Scan(ScanOptions{Path: tmpDir})
		if err != nil {
			fmt.Printf("Error scanning: %v\n", err)
		}
	}
}
