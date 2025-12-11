package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/seanhalberthal/supplyscan-mcp/internal/scanner"
	"github.com/seanhalberthal/supplyscan-mcp/internal/types"
)

// getStructuredContent returns the StructuredContent from a result.
func getStructuredContent[T any](t *testing.T, result *mcp.CallToolResultFor[T]) T {
	t.Helper()
	return result.StructuredContent
}

// setupTestScanner initialises the package-level scan variable for testing.
func setupTestScanner(t *testing.T) {
	t.Helper()
	s, err := scanner.New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}
	scan = s
}

// createTestProject creates a temporary directory with the given lockfiles.
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

// TestHandleStatus tests the status handler.
func TestHandleStatus(t *testing.T) {
	setupTestScanner(t)

	params := &mcp.CallToolParamsFor[statusInput]{
		Arguments: statusInput{},
	}

	result, err := handleStatus(context.Background(), nil, params)
	if err != nil {
		t.Fatalf("handleStatus() error = %v", err)
	}

	if result.IsError {
		t.Error("handleStatus() returned IsError = true")
	}

	// Verify status response structure
	status := getStructuredContent(t, result)
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
	setupTestScanner(t)

	projectDir := createTestProject(t, map[string]string{
		"package-lock.json": `{
			"name": "test",
			"lockfileVersion": 3,
			"packages": {
				"node_modules/lodash": {"version": "4.17.21"}
			}
		}`,
	})

	params := &mcp.CallToolParamsFor[scanInput]{
		Arguments: scanInput{
			Path:       projectDir,
			Recursive:  false,
			IncludeDev: true,
		},
	}

	result, err := handleScan(context.Background(), nil, params)
	if err != nil {
		t.Fatalf("handleScan() error = %v", err)
	}

	if result.IsError {
		t.Error("handleScan() returned IsError = true")
	}

	scanResult := getStructuredContent(t, result)
	if scanResult.Summary.LockfilesScanned != 1 {
		t.Errorf("LockfilesScanned = %d, want 1", scanResult.Summary.LockfilesScanned)
	}
	if scanResult.Summary.TotalDependencies != 1 {
		t.Errorf("TotalDependencies = %d, want 1", scanResult.Summary.TotalDependencies)
	}
}

func TestHandleScan_EmptyPath(t *testing.T) {
	setupTestScanner(t)

	params := &mcp.CallToolParamsFor[scanInput]{
		Arguments: scanInput{
			Path: "",
		},
	}

	result, err := handleScan(context.Background(), nil, params)

	if err == nil {
		t.Error("handleScan() expected error for empty path")
	}
	if result == nil || !result.IsError {
		t.Error("handleScan() expected IsError = true for empty path")
	}
	if err.Error() != "path is required" {
		t.Errorf("Error message = %q, want %q", err.Error(), "path is required")
	}
}

func TestHandleScan_InvalidPath(t *testing.T) {
	setupTestScanner(t)

	params := &mcp.CallToolParamsFor[scanInput]{
		Arguments: scanInput{
			Path: "/nonexistent/path/that/does/not/exist",
		},
	}

	result, err := handleScan(context.Background(), nil, params)

	if err == nil {
		t.Error("handleScan() expected error for invalid path")
	}
	if result == nil || !result.IsError {
		t.Error("handleScan() expected IsError = true for invalid path")
	}
}

func TestHandleScan_RecursiveOption(t *testing.T) {
	setupTestScanner(t)

	projectDir := createTestProject(t, map[string]string{
		"package-lock.json": `{
			"name": "root",
			"lockfileVersion": 3,
			"packages": {"node_modules/a": {"version": "1.0.0"}}
		}`,
		"packages/sub/package-lock.json": `{
			"name": "sub",
			"lockfileVersion": 3,
			"packages": {"node_modules/b": {"version": "1.0.0"}}
		}`,
	})

	// Non-recursive scan
	params := &mcp.CallToolParamsFor[scanInput]{
		Arguments: scanInput{
			Path:      projectDir,
			Recursive: false,
		},
	}

	result, err := handleScan(context.Background(), nil, params)
	if err != nil {
		t.Fatalf("handleScan() error = %v", err)
	}

	scanResult := getStructuredContent(t, result)
	if scanResult.Summary.LockfilesScanned != 1 {
		t.Errorf("Non-recursive: LockfilesScanned = %d, want 1", scanResult.Summary.LockfilesScanned)
	}

	// Recursive scan
	params.Arguments.Recursive = true
	result, err = handleScan(context.Background(), nil, params)
	if err != nil {
		t.Fatalf("handleScan() recursive error = %v", err)
	}

	recursiveResult := getStructuredContent(t, result)
	if recursiveResult.Summary.LockfilesScanned != 2 {
		t.Errorf("Recursive: LockfilesScanned = %d, want 2", recursiveResult.Summary.LockfilesScanned)
	}
}

func TestHandleCheck_ValidPackage(t *testing.T) {
	setupTestScanner(t)

	params := &mcp.CallToolParamsFor[checkInput]{
		Arguments: checkInput{
			Package: "lodash",
			Version: "4.17.21",
		},
	}

	result, err := handleCheck(context.Background(), nil, params)
	if err != nil {
		t.Fatalf("handleCheck() error = %v", err)
	}

	if result.IsError {
		t.Error("handleCheck() returned IsError = true")
	}

	checkResult := getStructuredContent(t, result)
	// lodash 4.17.21 is not a compromised package
	if checkResult.SupplyChain.Compromised {
		t.Error("Expected lodash@4.17.21 to not be compromised")
	}
}

func TestHandleCheck_EmptyPackage(t *testing.T) {
	setupTestScanner(t)

	params := &mcp.CallToolParamsFor[checkInput]{
		Arguments: checkInput{
			Package: "",
			Version: "1.0.0",
		},
	}

	result, err := handleCheck(context.Background(), nil, params)

	if err == nil {
		t.Error("handleCheck() expected error for empty package")
	}
	if result == nil || !result.IsError {
		t.Error("handleCheck() expected IsError = true for empty package")
	}
	if err.Error() != "package is required" {
		t.Errorf("Error message = %q, want %q", err.Error(), "package is required")
	}
}

func TestHandleCheck_EmptyVersion(t *testing.T) {
	setupTestScanner(t)

	params := &mcp.CallToolParamsFor[checkInput]{
		Arguments: checkInput{
			Package: "lodash",
			Version: "",
		},
	}

	result, err := handleCheck(context.Background(), nil, params)

	if err == nil {
		t.Error("handleCheck() expected error for empty version")
	}
	if result == nil || !result.IsError {
		t.Error("handleCheck() expected IsError = true for empty version")
	}
	if err.Error() != "version is required" {
		t.Errorf("Error message = %q, want %q", err.Error(), "version is required")
	}
}

func TestHandleCheck_BothEmpty(t *testing.T) {
	setupTestScanner(t)

	params := &mcp.CallToolParamsFor[checkInput]{
		Arguments: checkInput{
			Package: "",
			Version: "",
		},
	}

	result, err := handleCheck(context.Background(), nil, params)

	if err == nil {
		t.Error("handleCheck() expected error for empty inputs")
	}
	if result == nil || !result.IsError {
		t.Error("handleCheck() expected IsError = true for empty inputs")
	}
	// Package is checked first
	if err.Error() != "package is required" {
		t.Errorf("Error message = %q, want %q", err.Error(), "package is required")
	}
}

func TestHandleRefresh(t *testing.T) {
	setupTestScanner(t)

	params := &mcp.CallToolParamsFor[refreshInput]{
		Arguments: refreshInput{
			Force: false,
		},
	}

	result, err := handleRefresh(context.Background(), nil, params)
	if err != nil {
		t.Fatalf("handleRefresh() error = %v", err)
	}

	if result.IsError {
		t.Error("handleRefresh() returned IsError = true")
	}

	refreshResult := getStructuredContent(t, result)
	// PackagesCount and VersionsCount should be >= 0
	if refreshResult.PackagesCount < 0 {
		t.Errorf("PackagesCount = %d, want >= 0", refreshResult.PackagesCount)
	}
	if refreshResult.VersionsCount < 0 {
		t.Errorf("VersionsCount = %d, want >= 0", refreshResult.VersionsCount)
	}
}

func TestHandleRefresh_Force(t *testing.T) {
	setupTestScanner(t)

	params := &mcp.CallToolParamsFor[refreshInput]{
		Arguments: refreshInput{
			Force: true,
		},
	}

	result, err := handleRefresh(context.Background(), nil, params)
	if err != nil {
		t.Fatalf("handleRefresh() force error = %v", err)
	}

	if result.IsError {
		t.Error("handleRefresh() force returned IsError = true")
	}
}

// TestInputTypes verifies the input structs are properly structured.
func TestInputTypes(t *testing.T) {
	// Verify scanInput fields
	si := scanInput{
		Path:       "/test",
		Recursive:  true,
		IncludeDev: true,
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
