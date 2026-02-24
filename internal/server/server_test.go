package server

import (
	"context"
	"fmt"
	"testing"

	"github.com/seanhalberthal/supplyscan/internal/scanner"
	"github.com/seanhalberthal/supplyscan/internal/types"
)

// mockScanner implements scanner.Scanner for testing without network calls.
type mockScanner struct {
	scanResult    *types.ScanResult
	scanErr       error
	checkResult   *types.CheckResult
	checkErr      error
	refreshResult *types.RefreshResult
	refreshErr    error
	status        types.IOCDatabaseStatus
}

func (m *mockScanner) Scan(_ scanner.ScanOptions) (*types.ScanResult, error) {
	return m.scanResult, m.scanErr
}

func (m *mockScanner) CheckPackage(_, _ string) (*types.CheckResult, error) {
	return m.checkResult, m.checkErr
}

func (m *mockScanner) Refresh(_ bool) (*types.RefreshResult, error) {
	return m.refreshResult, m.refreshErr
}

func (m *mockScanner) GetStatus() types.IOCDatabaseStatus {
	return m.status
}

// setupMockScanner sets the package-level scan variable to a mock for testing.
func setupMockScanner(mock *mockScanner) {
	scan = mock
}

// newDefaultMock returns a mockScanner with sensible defaults.
func newDefaultMock() *mockScanner {
	return &mockScanner{
		scanResult: &types.ScanResult{
			Summary: types.ScanSummary{
				LockfilesScanned:  1,
				TotalDependencies: 1,
				Issues:            types.IssueCounts{},
			},
			SupplyChain: types.SupplyChainResult{
				Findings: []types.SupplyChainFinding{},
				Warnings: []types.SupplyChainWarning{},
			},
			Vulnerabilities: types.VulnerabilityResult{
				Findings: []types.VulnerabilityFinding{},
			},
			Lockfiles: []types.LockfileInfo{
				{Path: "package-lock.json", Type: "npm", Dependencies: 1},
			},
		},
		checkResult: &types.CheckResult{
			SupplyChain: types.CheckSupplyChainResult{
				Compromised: false,
			},
			Vulnerabilities: []types.VulnerabilityInfo{},
		},
		refreshResult: &types.RefreshResult{
			Updated:       false,
			PackagesCount: 100,
			VersionsCount: 200,
			CacheAgeHours: 1,
		},
		status: types.IOCDatabaseStatus{
			Packages:    100,
			Versions:    200,
			LastUpdated: "2024-01-01T00:00:00Z",
			Sources:     []string{"datadog"},
		},
	}
}

// TestHandleStatus tests the status handler.
func TestHandleStatus(t *testing.T) {
	mock := newDefaultMock()
	setupMockScanner(mock)

	_, status, err := handleStatus(context.Background(), nil, statusInput{})
	if err != nil {
		t.Fatalf("handleStatus() error = %v", err)
	}

	if status.Version != types.Version {
		t.Errorf("Version = %q, want %q", status.Version, types.Version)
	}
	if status.SupportedLockfiles == nil {
		t.Error("SupportedLockfiles is nil")
	}
	if len(status.SupportedLockfiles) == 0 {
		t.Error("SupportedLockfiles is empty")
	}
}

func TestHandleScan_ValidPath(t *testing.T) {
	mock := newDefaultMock()
	setupMockScanner(mock)

	includeDev := true
	_, scanResult, err := handleScan(context.Background(), nil, scanInput{
		Path:       "/tmp/test",
		Recursive:  false,
		IncludeDev: &includeDev,
	})
	if err != nil {
		t.Fatalf("handleScan() error = %v", err)
	}

	if scanResult.Summary.LockfilesScanned != 1 {
		t.Errorf("LockfilesScanned = %d, want 1", scanResult.Summary.LockfilesScanned)
	}
	if scanResult.Summary.TotalDependencies != 1 {
		t.Errorf("TotalDependencies = %d, want 1", scanResult.Summary.TotalDependencies)
	}
}

func TestHandleScan_EmptyPath(t *testing.T) {
	mock := newDefaultMock()
	setupMockScanner(mock)

	_, _, err := handleScan(context.Background(), nil, scanInput{Path: ""})

	if err == nil {
		t.Error("handleScan() expected error for empty path")
	}
	if err.Error() != "path is required" {
		t.Errorf("Error message = %q, want %q", err.Error(), "path is required")
	}
}

func TestHandleScan_InvalidPath(t *testing.T) {
	mock := &mockScanner{
		scanErr: fmt.Errorf("stat /nonexistent/path/that/does/not/exist: no such file or directory"),
	}
	setupMockScanner(mock)

	_, _, err := handleScan(context.Background(), nil, scanInput{
		Path: "/nonexistent/path/that/does/not/exist",
	})

	if err == nil {
		t.Error("handleScan() expected error for invalid path")
	}
}

func TestHandleScan_RecursiveOption(t *testing.T) {
	// Non-recursive scan: 1 lockfile
	mock := &mockScanner{
		scanResult: &types.ScanResult{
			Summary: types.ScanSummary{
				LockfilesScanned:  1,
				TotalDependencies: 1,
				Issues:            types.IssueCounts{},
			},
			SupplyChain:     types.SupplyChainResult{Findings: []types.SupplyChainFinding{}, Warnings: []types.SupplyChainWarning{}},
			Vulnerabilities: types.VulnerabilityResult{Findings: []types.VulnerabilityFinding{}},
			Lockfiles:       []types.LockfileInfo{{Path: "package-lock.json", Type: "npm", Dependencies: 1}},
		},
	}
	setupMockScanner(mock)

	_, scanResult, err := handleScan(context.Background(), nil, scanInput{
		Path:      "/tmp/test",
		Recursive: false,
	})
	if err != nil {
		t.Fatalf("handleScan() error = %v", err)
	}

	if scanResult.Summary.LockfilesScanned != 1 {
		t.Errorf("Non-recursive: LockfilesScanned = %d, want 1", scanResult.Summary.LockfilesScanned)
	}

	// Recursive scan: 2 lockfiles
	mock.scanResult = &types.ScanResult{
		Summary: types.ScanSummary{
			LockfilesScanned:  2,
			TotalDependencies: 2,
			Issues:            types.IssueCounts{},
		},
		SupplyChain:     types.SupplyChainResult{Findings: []types.SupplyChainFinding{}, Warnings: []types.SupplyChainWarning{}},
		Vulnerabilities: types.VulnerabilityResult{Findings: []types.VulnerabilityFinding{}},
		Lockfiles: []types.LockfileInfo{
			{Path: "package-lock.json", Type: "npm", Dependencies: 1},
			{Path: "packages/sub/package-lock.json", Type: "npm", Dependencies: 1},
		},
	}

	_, recursiveResult, err := handleScan(context.Background(), nil, scanInput{
		Path:      "/tmp/test",
		Recursive: true,
	})
	if err != nil {
		t.Fatalf("handleScan() recursive error = %v", err)
	}

	if recursiveResult.Summary.LockfilesScanned != 2 {
		t.Errorf("Recursive: LockfilesScanned = %d, want 2", recursiveResult.Summary.LockfilesScanned)
	}
}

func TestHandleScan_IncludeDevDefaultsToTrue(t *testing.T) {
	// When IncludeDev is nil (omitted), handler defaults to true,
	// so the mock returns 2 deps (both dev and non-dev included).
	mock := &mockScanner{
		scanResult: &types.ScanResult{
			Summary: types.ScanSummary{
				LockfilesScanned:  1,
				TotalDependencies: 2,
				Issues:            types.IssueCounts{},
			},
			SupplyChain:     types.SupplyChainResult{Findings: []types.SupplyChainFinding{}, Warnings: []types.SupplyChainWarning{}},
			Vulnerabilities: types.VulnerabilityResult{Findings: []types.VulnerabilityFinding{}},
			Lockfiles:       []types.LockfileInfo{{Path: "package-lock.json", Type: "npm", Dependencies: 2}},
		},
	}
	setupMockScanner(mock)

	_, scanResult, err := handleScan(context.Background(), nil, scanInput{
		Path:       "/tmp/test",
		Recursive:  false,
		IncludeDev: nil, // Explicitly nil to test default behaviour
	})
	if err != nil {
		t.Fatalf("handleScan() error = %v", err)
	}

	if scanResult.Summary.TotalDependencies != 2 {
		t.Errorf("TotalDependencies = %d, want 2 (dev dependencies should be included by default)", scanResult.Summary.TotalDependencies)
	}
}

func TestHandleScan_IncludeDevExplicitlyFalse(t *testing.T) {
	// When IncludeDev is explicitly false, mock returns 1 dep (dev excluded).
	mock := &mockScanner{
		scanResult: &types.ScanResult{
			Summary: types.ScanSummary{
				LockfilesScanned:  1,
				TotalDependencies: 1,
				Issues:            types.IssueCounts{},
			},
			SupplyChain:     types.SupplyChainResult{Findings: []types.SupplyChainFinding{}, Warnings: []types.SupplyChainWarning{}},
			Vulnerabilities: types.VulnerabilityResult{Findings: []types.VulnerabilityFinding{}},
			Lockfiles:       []types.LockfileInfo{{Path: "package-lock.json", Type: "npm", Dependencies: 1}},
		},
	}
	setupMockScanner(mock)

	includeDev := false
	_, scanResult, err := handleScan(context.Background(), nil, scanInput{
		Path:       "/tmp/test",
		Recursive:  false,
		IncludeDev: &includeDev,
	})
	if err != nil {
		t.Fatalf("handleScan() error = %v", err)
	}

	if scanResult.Summary.TotalDependencies != 1 {
		t.Errorf("TotalDependencies = %d, want 1 (dev dependencies should be excluded)", scanResult.Summary.TotalDependencies)
	}
}

func TestHandleCheck_ValidPackage(t *testing.T) {
	mock := newDefaultMock()
	setupMockScanner(mock)

	_, checkResult, err := handleCheck(context.Background(), nil, checkInput{
		Package: "lodash",
		Version: "4.17.21",
	})
	if err != nil {
		t.Fatalf("handleCheck() error = %v", err)
	}

	// lodash 4.17.21 is not a compromised package
	if checkResult.SupplyChain.Compromised {
		t.Error("Expected lodash@4.17.21 to not be compromised")
	}
}

func TestHandleCheck_EmptyPackage(t *testing.T) {
	mock := newDefaultMock()
	setupMockScanner(mock)

	_, _, err := handleCheck(context.Background(), nil, checkInput{
		Package: "",
		Version: "1.0.0",
	})

	if err == nil {
		t.Error("handleCheck() expected error for empty package")
	}
	if err.Error() != "package is required" {
		t.Errorf("Error message = %q, want %q", err.Error(), "package is required")
	}
}

func TestHandleCheck_EmptyVersion(t *testing.T) {
	mock := newDefaultMock()
	setupMockScanner(mock)

	_, _, err := handleCheck(context.Background(), nil, checkInput{
		Package: "lodash",
		Version: "",
	})

	if err == nil {
		t.Error("handleCheck() expected error for empty version")
	}
	if err.Error() != "version is required" {
		t.Errorf("Error message = %q, want %q", err.Error(), "version is required")
	}
}

func TestHandleCheck_BothEmpty(t *testing.T) {
	mock := newDefaultMock()
	setupMockScanner(mock)

	_, _, err := handleCheck(context.Background(), nil, checkInput{
		Package: "",
		Version: "",
	})

	if err == nil {
		t.Error("handleCheck() expected error for empty inputs")
	}
	// Package is checked first
	if err.Error() != "package is required" {
		t.Errorf("Error message = %q, want %q", err.Error(), "package is required")
	}
}

func TestHandleRefresh(t *testing.T) {
	mock := newDefaultMock()
	setupMockScanner(mock)

	_, refreshResult, err := handleRefresh(context.Background(), nil, refreshInput{
		Force: false,
	})
	if err != nil {
		t.Fatalf("handleRefresh() error = %v", err)
	}

	if refreshResult.PackagesCount < 0 {
		t.Errorf("PackagesCount = %d, want >= 0", refreshResult.PackagesCount)
	}
	if refreshResult.VersionsCount < 0 {
		t.Errorf("VersionsCount = %d, want >= 0", refreshResult.VersionsCount)
	}
}

func TestHandleRefresh_Force(t *testing.T) {
	mock := newDefaultMock()
	mock.refreshResult = &types.RefreshResult{
		Updated:       true,
		PackagesCount: 150,
		VersionsCount: 300,
		CacheAgeHours: 0,
	}
	setupMockScanner(mock)

	_, _, err := handleRefresh(context.Background(), nil, refreshInput{
		Force: true,
	})
	if err != nil {
		t.Fatalf("handleRefresh() force error = %v", err)
	}
}

// TestInputTypes verifies the input structs are properly structured.
func TestInputTypes(t *testing.T) {
	// Verify scanInput fields
	includeDev := true
	si := scanInput{
		Path:       "/test",
		Recursive:  true,
		IncludeDev: &includeDev,
	}
	if si.Path != "/test" {
		t.Errorf("scanInput.Path = %q, want /test", si.Path)
	}

	// Verify checkInput fields
	ci := checkInput{
		Package: "lodash",
		Version: "4.17.21",
	}
	if ci.Package != "lodash" || ci.Version != "4.17.21" {
		t.Error("checkInput fields not set correctly")
	}

	// Verify refreshInput fields
	ri := refreshInput{Force: true}
	if !ri.Force {
		t.Error("refreshInput.Force not set correctly")
	}
}

// TestOutputTypes verifies the output structs embed types correctly.
func TestOutputTypes(t *testing.T) {
	// statusOutput embeds StatusResponse
	so := statusOutput{
		StatusResponse: types.StatusResponse{
			Version: types.Version,
		},
	}
	if so.Version != types.Version {
		t.Errorf("statusOutput.Version = %q, want %s", so.Version, types.Version)
	}

	// scanOutput embeds ScanResult
	sco := scanOutput{
		ScanResult: types.ScanResult{
			Summary: types.ScanSummary{LockfilesScanned: 5},
		},
	}
	if sco.Summary.LockfilesScanned != 5 {
		t.Errorf("scanOutput.Summary.LockfilesScanned = %d, want 5", sco.Summary.LockfilesScanned)
	}

	// checkOutput embeds CheckResult
	co := checkOutput{
		CheckResult: types.CheckResult{
			SupplyChain: types.CheckSupplyChainResult{Compromised: true},
		},
	}
	if !co.SupplyChain.Compromised {
		t.Error("checkOutput.SupplyChain.Compromised not set correctly")
	}

	// refreshOutput embeds RefreshResult
	ro := refreshOutput{
		RefreshResult: types.RefreshResult{Updated: true, PackagesCount: 100},
	}
	if !ro.Updated || ro.PackagesCount != 100 {
		t.Error("refreshOutput fields not set correctly")
	}
}
