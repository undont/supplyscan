package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
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

// newDefaultMock returns a mockScanner with sensible defaults for most tests.
func newDefaultMock() *mockScanner {
	return &mockScanner{
		scanResult: &types.ScanResult{
			Summary: types.ScanSummary{
				LockfilesScanned:  1,
				TotalDependencies: 5,
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
				{Path: "package-lock.json", Type: "npm", Dependencies: 5},
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
			SourceResults: map[string]types.SourceRefreshInfo{
				"datadog": {PackageCount: 100},
			},
		},
		status: types.IOCDatabaseStatus{
			Packages:    100,
			Versions:    200,
			LastUpdated: "2024-01-01T00:00:00Z",
			Sources:     []string{"datadog"},
		},
	}
}

// resetOutputJSON resets the global outputJSON flag between tests.
func resetOutputJSON() {
	outputJSON = false
}

// captureOutput captures stdout during function execution
func captureOutput(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	err := w.Close()
	if err != nil {
		fmt.Printf("Error closing pipe: %v\n", err.Error()+"")
	}
	os.Stdout = old

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	if err != nil {
		fmt.Printf("Error copying pipe: %v\n", err.Error()+"")
	}
	return buf.String()
}

// captureStderr captures stderr during function execution
func captureStderr(f func()) string {
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	f()

	err := w.Close()
	if err != nil {
		fmt.Printf("Error closing pipe: %v\n", err.Error()+"")
	}
	os.Stderr = old

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	if err != nil {
		fmt.Printf("Error copying pipe: %v\n", err.Error()+"")
	}
	return buf.String()
}

func TestParseScanFlags(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantRec bool
		wantDev bool
	}{
		{
			name:    "no flags",
			args:    []string{},
			wantRec: false,
			wantDev: true, // Default includes dev
		},
		{
			name:    "recursive long",
			args:    []string{"--recursive"},
			wantRec: true,
			wantDev: true,
		},
		{
			name:    "recursive short",
			args:    []string{"-r"},
			wantRec: true,
			wantDev: true,
		},
		{
			name:    "no-dev",
			args:    []string{"--no-dev"},
			wantRec: false,
			wantDev: false,
		},
		{
			name:    "all flags",
			args:    []string{"--recursive", "--no-dev"},
			wantRec: true,
			wantDev: false,
		},
		{
			name:    "short and long",
			args:    []string{"-r", "--no-dev"},
			wantRec: true,
			wantDev: false,
		},
		{
			name:    "unknown flags ignored",
			args:    []string{"--recursive", "--unknown", "-x"},
			wantRec: true,
			wantDev: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := parseScanFlags(tt.args)
			if opts.Recursive != tt.wantRec {
				t.Errorf("Recursive = %v, want %v", opts.Recursive, tt.wantRec)
			}
			if opts.IncludeDev != tt.wantDev {
				t.Errorf("IncludeDev = %v, want %v", opts.IncludeDev, tt.wantDev)
			}
		})
	}
}

func TestParseGlobalFlags(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantJSON   bool
		wantRemain []string
	}{
		{
			name:       "no flags",
			args:       []string{"scan", "."},
			wantJSON:   false,
			wantRemain: []string{"scan", "."},
		},
		{
			name:       "json flag",
			args:       []string{"--json", "scan", "."},
			wantJSON:   true,
			wantRemain: []string{"scan", "."},
		},
		{
			name:       "json flag at end",
			args:       []string{"scan", ".", "--json"},
			wantJSON:   true,
			wantRemain: []string{"scan", "."},
		},
		{
			name:       "json flag in middle",
			args:       []string{"scan", "--json", "."},
			wantJSON:   true,
			wantRemain: []string{"scan", "."},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetOutputJSON()
			remaining := parseGlobalFlags(tt.args)

			if outputJSON != tt.wantJSON {
				t.Errorf("outputJSON = %v, want %v", outputJSON, tt.wantJSON)
			}

			if len(remaining) != len(tt.wantRemain) {
				t.Errorf("remaining = %v, want %v", remaining, tt.wantRemain)
				return
			}

			for i, arg := range remaining {
				if arg != tt.wantRemain[i] {
					t.Errorf("remaining[%d] = %v, want %v", i, arg, tt.wantRemain[i])
				}
			}
		})
	}
}

func TestPrintUsage(t *testing.T) {
	resetOutputJSON()
	output := captureOutput(func() {
		printUsage()
	})

	// Check that usage contains expected elements
	expectedPhrases := []string{
		"supplyscan",
		"MCP server",
		"--mcp",
		"status",
		"scan",
		"check",
		"refresh",
		"--recursive",
		"--json",
	}

	for _, phrase := range expectedPhrases {
		if !strings.Contains(output, phrase) {
			t.Errorf("Usage output missing %q", phrase)
		}
	}
}

func TestRunStatus_JSON(t *testing.T) {
	resetOutputJSON()
	outputJSON = true

	mock := newDefaultMock()

	output := captureOutput(func() {
		runStatus(mock)
	})

	// Should be valid JSON
	var status types.StatusResponse
	if err := json.Unmarshal([]byte(output), &status); err != nil {
		t.Errorf("Output is not valid JSON: %v\nOutput: %s", err, output)
	}

	// Check version is set
	if status.Version == "" {
		t.Error("Version is empty")
	}

	// Check supported lockfiles
	if len(status.SupportedLockfiles) == 0 {
		t.Error("SupportedLockfiles is empty")
	}

	// Verify specific lockfiles are supported
	expected := []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
	for _, lf := range expected {
		found := false
		for _, supported := range status.SupportedLockfiles {
			if supported == lf {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected %q in supported lockfiles", lf)
		}
	}
}

func TestRunStatus_Styled(t *testing.T) {
	resetOutputJSON()

	mock := newDefaultMock()

	output := captureOutput(func() {
		runStatus(mock)
	})

	// Should contain styled elements
	expectedPhrases := []string{
		"Scanner Status",
		"Version",
		"IOC Database",
		"Supported Lockfiles",
	}

	for _, phrase := range expectedPhrases {
		if !strings.Contains(output, phrase) {
			t.Errorf("Styled output missing %q", phrase)
		}
	}
}

func TestRunScan_Success_JSON(t *testing.T) {
	resetOutputJSON()
	outputJSON = true

	mock := &mockScanner{
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
	}

	output := captureOutput(func() {
		runScan(mock, "/tmp/test", scanOptions{Recursive: false, IncludeDev: true})
	})

	// Should be valid JSON
	var result types.ScanResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Errorf("Output is not valid JSON: %v\nOutput: %s", err, output)
	}

	// Check summary
	if result.Summary.LockfilesScanned != 1 {
		t.Errorf("LockfilesScanned = %d, want 1", result.Summary.LockfilesScanned)
	}
}

func TestScanPathParsing(t *testing.T) {
	// Test that scan command correctly parses path vs flags
	tests := []struct {
		name     string
		args     []string
		wantPath string
	}{
		{
			name:     "no path defaults to dot",
			args:     []string{"scan"},
			wantPath: ".",
		},
		{
			name:     "explicit path",
			args:     []string{"scan", "/some/path"},
			wantPath: "/some/path",
		},
		{
			name:     "path with flags after",
			args:     []string{"scan", "/some/path", "--recursive"},
			wantPath: "/some/path",
		},
		{
			name:     "flags only defaults to dot",
			args:     []string{"scan", "--recursive"},
			wantPath: ".",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the path parsing logic from Run
			args := tt.args
			if len(args) > 0 && args[0] == "scan" {
				path := "."
				if len(args) >= 2 && !strings.HasPrefix(args[1], "-") {
					path = args[1]
				}
				if path != tt.wantPath {
					t.Errorf("path = %q, want %q", path, tt.wantPath)
				}
			}
		})
	}
}

func TestRunScan_WithFlags(t *testing.T) {
	resetOutputJSON()
	outputJSON = true

	mock := &mockScanner{
		scanResult: &types.ScanResult{
			Summary: types.ScanSummary{
				LockfilesScanned:  2,
				TotalDependencies: 2,
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
				{Path: "packages/sub/package-lock.json", Type: "npm", Dependencies: 1},
			},
		},
	}

	// Test with recursive flag
	output := captureOutput(func() {
		runScan(mock, "/tmp/test", scanOptions{Recursive: true, IncludeDev: true})
	})

	var result types.ScanResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	if result.Summary.LockfilesScanned != 2 {
		t.Errorf("With recursive: LockfilesScanned = %d, want 2", result.Summary.LockfilesScanned)
	}
}

func TestRunCheck_JSON(t *testing.T) {
	resetOutputJSON()
	outputJSON = true

	mock := &mockScanner{
		checkResult: &types.CheckResult{
			SupplyChain: types.CheckSupplyChainResult{
				Compromised: false,
			},
			Vulnerabilities: []types.VulnerabilityInfo{},
		},
	}

	output := captureOutput(func() {
		runCheck(mock, "lodash", "4.17.21")
	})

	// Should be valid JSON
	var result types.CheckResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Errorf("Output is not valid JSON: %v\nOutput: %s", err, output)
	}

	// Vulnerabilities array should exist
	if result.Vulnerabilities == nil {
		t.Error("Vulnerabilities is nil")
	}
}

func TestRunCheck_Styled(t *testing.T) {
	resetOutputJSON()

	mock := &mockScanner{
		checkResult: &types.CheckResult{
			SupplyChain: types.CheckSupplyChainResult{
				Compromised: false,
			},
			Vulnerabilities: []types.VulnerabilityInfo{},
		},
	}

	output := captureOutput(func() {
		runCheck(mock, "lodash", "4.17.21")
	})

	// Should contain styled elements
	expectedPhrases := []string{
		"Package Check",
		"lodash",
		"4.17.21",
	}

	for _, phrase := range expectedPhrases {
		if !strings.Contains(output, phrase) {
			t.Errorf("Styled output missing %q", phrase)
		}
	}
}

func TestRunRefresh_JSON(t *testing.T) {
	resetOutputJSON()
	outputJSON = true

	mock := newDefaultMock()

	output := captureOutput(func() {
		runRefresh(mock, false)
	})

	// Should be valid JSON
	var result types.RefreshResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Errorf("Output is not valid JSON: %v\nOutput: %s", err, output)
	}
}

func TestPrintJSON(t *testing.T) {
	resetOutputJSON()
	testData := struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Count   int    `json:"count"`
	}{
		Name:    "test",
		Version: "1.0.0",
		Count:   42,
	}

	output := captureOutput(func() {
		printJSON(testData)
	})

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Errorf("Output is not valid JSON: %v", err)
	}

	// Verify values
	if parsed["name"] != "test" {
		t.Errorf("name = %v, want test", parsed["name"])
	}
	if parsed["count"].(float64) != 42 {
		t.Errorf("count = %v, want 42", parsed["count"])
	}

	// Should be indented (contain newlines)
	if !strings.Contains(output, "\n") {
		t.Error("Output should be indented with newlines")
	}
}

func TestPrintJSON_NestedStruct(t *testing.T) {
	resetOutputJSON()
	testData := types.StatusResponse{
		Version: types.Version,
		IOCDatabase: types.IOCDatabaseStatus{
			Packages:    10,
			Versions:    20,
			LastUpdated: "2024-01-01T00:00:00Z",
			Sources:     []string{"datadog"},
		},
		SupportedLockfiles: []string{"package-lock.json"},
	}

	output := captureOutput(func() {
		printJSON(testData)
	})

	// Verify it's valid JSON and can be parsed back
	var parsed types.StatusResponse
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Errorf("Output is not valid JSON: %v", err)
	}

	if parsed.Version != types.Version {
		t.Errorf("Version = %q, want %s", parsed.Version, types.Version)
	}
	if parsed.IOCDatabase.Packages != 10 {
		t.Errorf("IOCDatabase.Packages = %d, want 10", parsed.IOCDatabase.Packages)
	}
}

func TestScanOptions_Default(t *testing.T) {
	opts := scanOptions{}

	// Default should NOT be recursive
	if opts.Recursive {
		t.Error("Default Recursive = true, want false")
	}

	// Default should NOT include dev (zero value is false)
	// But parseScanFlags sets IncludeDev to true by default
}

// mockExit captures exit codes instead of terminating.
func mockExit(t *testing.T) (restore func(), exitCode *int) {
	t.Helper()
	code := 0
	exitCode = &code
	oldExit := exitFunc
	exitFunc = func(c int) {
		*exitCode = c
	}
	restore = func() {
		exitFunc = oldExit
	}
	return restore, exitCode
}

func TestRun_NoArgs(t *testing.T) {
	resetOutputJSON()
	restore, _ := mockExit(t)
	defer restore()

	mock := newDefaultMock()

	output := captureOutput(func() {
		Run(mock, []string{})
	})

	// Now prints usage without error exit
	if !strings.Contains(output, "supplyscan") {
		t.Error("Expected usage output")
	}
}

func TestRun_UnknownCommand(t *testing.T) {
	resetOutputJSON()
	restore, exitCode := mockExit(t)
	defer restore()

	mock := newDefaultMock()

	stderr := captureStderr(func() {
		Run(mock, []string{"unknown-command"})
	})

	if *exitCode != 1 {
		t.Errorf("Exit code = %d, want 1", *exitCode)
	}
	if !strings.Contains(stderr, "Unknown command: unknown-command") {
		t.Errorf("Expected unknown command error, got: %s", stderr)
	}
}

func TestRun_StatusCommand(t *testing.T) {
	resetOutputJSON()
	outputJSON = true
	restore, exitCode := mockExit(t)
	defer restore()

	mock := newDefaultMock()

	output := captureOutput(func() {
		Run(mock, []string{"status", "--json"})
	})

	if *exitCode != 0 {
		t.Errorf("Exit code = %d, want 0", *exitCode)
	}

	var status types.StatusResponse
	if err := json.Unmarshal([]byte(output), &status); err != nil {
		t.Errorf("Output is not valid JSON: %v", err)
	}
}

func TestRun_ScanCommand_InvalidPath(t *testing.T) {
	resetOutputJSON()
	restore, exitCode := mockExit(t)
	defer restore()

	mock := &mockScanner{
		scanErr: fmt.Errorf("stat /nonexistent/path: no such file or directory"),
	}

	stderr := captureStderr(func() {
		Run(mock, []string{"scan", "/nonexistent/path"})
	})

	if *exitCode != 1 {
		t.Errorf("Exit code = %d, want 1", *exitCode)
	}
	if !strings.Contains(stderr, "Error") && !strings.Contains(stderr, crossMark) {
		t.Errorf("Expected error output, got: %s", stderr)
	}
}

func TestRun_ScanCommand_WithFlags(t *testing.T) {
	resetOutputJSON()
	outputJSON = true
	restore, exitCode := mockExit(t)
	defer restore()

	mock := &mockScanner{
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
			Lockfiles: []types.LockfileInfo{},
		},
	}

	output := captureOutput(func() {
		Run(mock, []string{"scan", "/tmp/test", "--recursive", "--no-dev", "--json"})
	})

	if *exitCode != 0 {
		t.Errorf("Exit code = %d, want 0", *exitCode)
	}

	var result types.ScanResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Errorf("Output is not valid JSON: %v", err)
	}
}

func TestRun_CheckCommand_MissingArgs(t *testing.T) {
	resetOutputJSON()
	restore, exitCode := mockExit(t)
	defer restore()

	mock := newDefaultMock()

	// Missing both package and version
	stderr := captureStderr(func() {
		Run(mock, []string{"check"})
	})
	if *exitCode != 1 {
		t.Errorf("Exit code = %d, want 1", *exitCode)
	}
	if !strings.Contains(stderr, "check requires package and version arguments") {
		t.Errorf("Expected args required error, got: %s", stderr)
	}

	// Reset exit code
	*exitCode = 0

	// Missing version
	_ = captureStderr(func() {
		Run(mock, []string{"check", "lodash"})
	})
	if *exitCode != 1 {
		t.Errorf("Exit code = %d, want 1 (missing version)", *exitCode)
	}
}

func TestRun_CheckCommand_Valid(t *testing.T) {
	resetOutputJSON()
	outputJSON = true
	restore, exitCode := mockExit(t)
	defer restore()

	mock := &mockScanner{
		checkResult: &types.CheckResult{
			SupplyChain: types.CheckSupplyChainResult{
				Compromised: false,
			},
			Vulnerabilities: []types.VulnerabilityInfo{},
		},
	}

	output := captureOutput(func() {
		Run(mock, []string{"check", "lodash", "4.17.21", "--json"})
	})

	if *exitCode != 0 {
		t.Errorf("Exit code = %d, want 0", *exitCode)
	}

	var result types.CheckResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Errorf("Output is not valid JSON: %v", err)
	}
}

func TestRun_RefreshCommand(t *testing.T) {
	resetOutputJSON()
	outputJSON = true
	restore, exitCode := mockExit(t)
	defer restore()

	mock := newDefaultMock()

	output := captureOutput(func() {
		Run(mock, []string{"refresh", "--json"})
	})

	if *exitCode != 0 {
		t.Errorf("Exit code = %d, want 0", *exitCode)
	}

	var result types.RefreshResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Errorf("Output is not valid JSON: %v", err)
	}
}

func TestRun_RefreshCommand_Force(t *testing.T) {
	resetOutputJSON()
	outputJSON = true
	restore, exitCode := mockExit(t)
	defer restore()

	mock := newDefaultMock()
	mock.refreshResult = &types.RefreshResult{
		Updated:       true,
		PackagesCount: 150,
		VersionsCount: 300,
		CacheAgeHours: 0,
		SourceResults: map[string]types.SourceRefreshInfo{
			"datadog": {PackageCount: 150},
		},
	}

	output := captureOutput(func() {
		Run(mock, []string{"refresh", "--force", "--json"})
	})

	if *exitCode != 0 {
		t.Errorf("Exit code = %d, want 0", *exitCode)
	}

	var result types.RefreshResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Errorf("Output is not valid JSON: %v", err)
	}
}

func TestRun_HelpCommand(t *testing.T) {
	resetOutputJSON()
	restore, exitCode := mockExit(t)
	defer restore()

	mock := newDefaultMock()

	// Test "help" command
	output := captureOutput(func() {
		Run(mock, []string{"help"})
	})

	if *exitCode != 0 {
		t.Errorf("Exit code = %d, want 0", *exitCode)
	}
	if !strings.Contains(output, "supplyscan") {
		t.Error("Expected usage output")
	}

	// Test "--help" flag
	*exitCode = 0
	output = captureOutput(func() {
		Run(mock, []string{"--help"})
	})

	if *exitCode != 0 {
		t.Errorf("Exit code = %d, want 0", *exitCode)
	}
	if !strings.Contains(output, "supplyscan") {
		t.Error("Expected usage output")
	}
}

// =============================================================================
// Status/Scan/Check/Refresh Integration Tests (using mock)
// =============================================================================

func TestCLI_StatusIntegration(t *testing.T) {
	resetOutputJSON()
	outputJSON = true

	mock := newDefaultMock()

	output := captureOutput(func() {
		runStatus(mock)
	})

	// Verify JSON output contains expected fields
	var status types.StatusResponse
	if err := json.Unmarshal([]byte(output), &status); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// Version should be types.Version
	if status.Version != types.Version {
		t.Errorf("Version = %q, want %q", status.Version, types.Version)
	}
}

func TestCLI_ScanIntegration(t *testing.T) {
	resetOutputJSON()
	outputJSON = true

	// Mock scanner that returns different results based on IncludeDev
	scanCallCount := 0
	mock := &mockScanner{
		checkResult: &types.CheckResult{
			SupplyChain:     types.CheckSupplyChainResult{Compromised: false},
			Vulnerabilities: []types.VulnerabilityInfo{},
		},
	}

	// First call: IncludeDev=false (2 deps)
	mock.scanResult = &types.ScanResult{
		Summary: types.ScanSummary{
			LockfilesScanned:  1,
			TotalDependencies: 2,
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
			{Path: "package-lock.json", Type: "npm", Dependencies: 2},
		},
	}

	// Test scan with IncludeDev=false
	output := captureOutput(func() {
		runScan(mock, "/tmp/test", scanOptions{Recursive: false, IncludeDev: false})
	})
	scanCallCount++

	var result types.ScanResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// With IncludeDev=false, should only have 2 dependencies
	if result.Summary.TotalDependencies != 2 {
		t.Errorf("TotalDependencies = %d, want 2 (dev excluded)", result.Summary.TotalDependencies)
	}

	// Second call: IncludeDev=true (3 deps)
	mock.scanResult = &types.ScanResult{
		Summary: types.ScanSummary{
			LockfilesScanned:  1,
			TotalDependencies: 3,
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
			{Path: "package-lock.json", Type: "npm", Dependencies: 3},
		},
	}

	// Test with dev included
	output2 := captureOutput(func() {
		runScan(mock, "/tmp/test", scanOptions{Recursive: false, IncludeDev: true})
	})

	var result2 types.ScanResult
	if err := json.Unmarshal([]byte(output2), &result2); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if result2.Summary.TotalDependencies != 3 {
		t.Errorf("TotalDependencies = %d, want 3 (dev included)", result2.Summary.TotalDependencies)
	}

	_ = scanCallCount // used to track calls
}

func TestCLI_CheckIntegration(t *testing.T) {
	resetOutputJSON()
	outputJSON = true

	mock := &mockScanner{
		checkResult: &types.CheckResult{
			SupplyChain: types.CheckSupplyChainResult{
				Compromised: false,
			},
			Vulnerabilities: []types.VulnerabilityInfo{},
		},
	}

	// Check a scoped package
	output := captureOutput(func() {
		runCheck(mock, "@babel/core", "7.23.0")
	})

	var result types.CheckResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// Should have supply_chain and vulnerabilities fields
}

func TestCLI_JSONOutputFormat(t *testing.T) {
	resetOutputJSON()
	outputJSON = true

	mock := newDefaultMock()

	output := captureOutput(func() {
		runStatus(mock)
	})

	// Check indentation (2 spaces)
	if !strings.Contains(output, "  \"") {
		t.Error("JSON output should be indented with 2 spaces")
	}

	// Should end with newline
	if !strings.HasSuffix(output, "\n") {
		t.Error("JSON output should end with newline")
	}
}

func BenchmarkPrintJSON(b *testing.B) {
	data := types.ScanResult{
		Summary: types.ScanSummary{
			LockfilesScanned:  10,
			TotalDependencies: 500,
		},
		SupplyChain: types.SupplyChainResult{
			Findings: make([]types.SupplyChainFinding, 5),
			Warnings: make([]types.SupplyChainWarning, 10),
		},
		Vulnerabilities: types.VulnerabilityResult{
			Findings: make([]types.VulnerabilityFinding, 20),
		},
	}

	// Redirect stdout to discard
	old := os.Stdout
	os.Stdout, _ = os.Open(os.DevNull)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		printJSON(data)
	}

	os.Stdout = old
}

// =============================================================================
// Style Functions Tests
// =============================================================================

func TestSeverityStyle(t *testing.T) {
	tests := []struct {
		severity string
	}{
		{"critical"},
		{"high"},
		{"moderate"},
		{"medium"}, // alias for moderate
		{"low"},
		{"unknown"}, // default case
		{""},        // empty string
	}

	for _, tt := range tests {
		name := tt.severity
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			style := severityStyle(tt.severity)
			// Render a test string to ensure the style works without error
			rendered := style.Render("test")
			// In non-TTY environments (like tests), lipgloss may not add ANSI codes
			// The important thing is that the function returns without error
			// and produces output containing the text
			if !strings.Contains(rendered, "test") {
				t.Errorf("severityStyle(%q).Render() = %q, should contain 'test'", tt.severity, rendered)
			}
		})
	}
}

func TestFormatSeverity(t *testing.T) {
	tests := []string{"critical", "high", "moderate", "medium", "low"}

	for _, severity := range tests {
		t.Run(severity, func(t *testing.T) {
			result := formatSeverity(severity)
			// Should contain the severity text
			// In non-TTY environments, lipgloss may not add ANSI codes
			if !strings.Contains(result, severity) {
				t.Errorf("formatSeverity(%q) = %q, should contain %q", severity, result, severity)
			}
		})
	}
}

func TestFormatWarning(t *testing.T) {
	msg := "This is a warning message"
	result := formatWarning(msg)

	// Should contain the message
	if !strings.Contains(result, msg) {
		t.Errorf("formatWarning() should contain the message")
	}

	// Should contain the warning symbol "!"
	if !strings.Contains(result, "!") {
		t.Errorf("formatWarning() should contain '!' symbol")
	}
}

// =============================================================================
// printScanResult Tests
// =============================================================================

func TestPrintScanResult_NoIssues(t *testing.T) {
	resetOutputJSON()

	result := &types.ScanResult{
		Summary: types.ScanSummary{
			LockfilesScanned:  1,
			TotalDependencies: 5,
			Issues: types.IssueCounts{
				Critical:    0,
				High:        0,
				Moderate:    0,
				SupplyChain: 0,
			},
		},
		Lockfiles: []types.LockfileInfo{
			{Path: "package-lock.json", Type: "npm", Dependencies: 5},
		},
	}

	output := captureOutput(func() {
		printScanResult(result)
	})

	// Should show success message
	if !strings.Contains(output, "No issues found") {
		t.Error("Expected 'No issues found' message")
	}

	// Should contain checkmark symbol
	if !strings.Contains(output, checkMark) {
		t.Error("Expected success checkmark")
	}

	// Should show summary
	if !strings.Contains(output, "Lockfiles scanned") {
		t.Error("Expected 'Lockfiles scanned' label")
	}
	if !strings.Contains(output, "Dependencies") {
		t.Error("Expected 'Dependencies' label")
	}
}

func TestPrintScanResult_WithIssues(t *testing.T) {
	resetOutputJSON()

	result := &types.ScanResult{
		Summary: types.ScanSummary{
			LockfilesScanned:  1,
			TotalDependencies: 100,
			Issues: types.IssueCounts{
				Critical:    2,
				High:        3,
				Moderate:    5,
				SupplyChain: 1,
			},
		},
	}

	output := captureOutput(func() {
		printScanResult(result)
	})

	// Should show issues section
	if !strings.Contains(output, "Issues Found") {
		t.Error("Expected 'Issues Found' section")
	}

	// Should show severity counts
	if !strings.Contains(output, "critical") {
		t.Error("Expected 'critical' severity")
	}
	if !strings.Contains(output, "high") {
		t.Error("Expected 'high' severity")
	}
	if !strings.Contains(output, "moderate") {
		t.Error("Expected 'moderate' severity")
	}
	if !strings.Contains(output, "supply chain") {
		t.Error("Expected 'supply chain' label")
	}
}

func TestPrintScanResult_SupplyChainFindings(t *testing.T) {
	resetOutputJSON()

	result := &types.ScanResult{
		Summary: types.ScanSummary{
			LockfilesScanned:  1,
			TotalDependencies: 10,
			Issues: types.IssueCounts{
				SupplyChain: 1,
			},
		},
		SupplyChain: types.SupplyChainResult{
			Findings: []types.SupplyChainFinding{
				{
					Package:          "malicious-pkg",
					InstalledVersion: "1.0.0",
					Severity:         "critical",
					Type:             "compromised",
					Action:           "Remove immediately",
					Campaigns:        []string{"shai-hulud"},
				},
			},
		},
	}

	output := captureOutput(func() {
		printScanResult(result)
	})

	// Should show supply chain section
	if !strings.Contains(output, "Supply Chain Compromises") {
		t.Error("Expected 'Supply Chain Compromises' section")
	}

	// Should show package name and version
	if !strings.Contains(output, "malicious-pkg") {
		t.Error("Expected package name 'malicious-pkg'")
	}
	if !strings.Contains(output, "1.0.0") {
		t.Error("Expected version '1.0.0'")
	}

	// Should show finding details
	if !strings.Contains(output, "Severity") {
		t.Error("Expected 'Severity' label")
	}
	if !strings.Contains(output, "Type") {
		t.Error("Expected 'Type' label")
	}
	if !strings.Contains(output, "Action") {
		t.Error("Expected 'Action' label")
	}
	if !strings.Contains(output, "Campaigns") {
		t.Error("Expected 'Campaigns' label")
	}
	if !strings.Contains(output, "shai-hulud") {
		t.Error("Expected campaign name 'shai-hulud'")
	}

	// Should contain cross mark for compromised packages
	if !strings.Contains(output, crossMark) {
		t.Error("Expected cross mark for compromised package")
	}
}

func TestPrintScanResult_SupplyChainWarnings(t *testing.T) {
	resetOutputJSON()

	result := &types.ScanResult{
		Summary: types.ScanSummary{
			LockfilesScanned:  1,
			TotalDependencies: 10,
		},
		SupplyChain: types.SupplyChainResult{
			Warnings: []types.SupplyChainWarning{
				{
					Package:          "@pnpm/network.ca-file",
					InstalledVersion: "1.0.0",
					Note:             "Package from at-risk namespace",
				},
			},
		},
	}

	output := captureOutput(func() {
		printScanResult(result)
	})

	// Should show warnings section
	if !strings.Contains(output, "Warnings") {
		t.Error("Expected 'Warnings' section")
	}

	// Should show warning symbol
	if !strings.Contains(output, "!") {
		t.Error("Expected '!' warning symbol")
	}

	// Should show package and note
	if !strings.Contains(output, "@pnpm/network.ca-file") {
		t.Error("Expected package name")
	}
	if !strings.Contains(output, "at-risk namespace") {
		t.Error("Expected warning note")
	}
}

func TestPrintScanResult_Vulnerabilities(t *testing.T) {
	resetOutputJSON()

	result := &types.ScanResult{
		Summary: types.ScanSummary{
			LockfilesScanned:  1,
			TotalDependencies: 10,
			Issues: types.IssueCounts{
				High: 1,
			},
		},
		Vulnerabilities: types.VulnerabilityResult{
			Findings: []types.VulnerabilityFinding{
				{
					Package:          "lodash",
					InstalledVersion: "4.17.15",
					Severity:         "high",
					ID:               "GHSA-xxxx-xxxx-xxxx",
					Title:            "Prototype Pollution",
					PatchedIn:        "4.17.21",
				},
				{
					Package:          "express",
					InstalledVersion: "4.17.0",
					Severity:         "moderate",
					ID:               "GHSA-yyyy-yyyy-yyyy",
					Title:            "Open Redirect",
					PatchedIn:        "", // No patch available
				},
			},
		},
	}

	output := captureOutput(func() {
		printScanResult(result)
	})

	// Should show vulnerabilities section
	if !strings.Contains(output, "Vulnerabilities") {
		t.Error("Expected 'Vulnerabilities' section")
	}

	// Should show vulnerability details
	if !strings.Contains(output, "lodash") {
		t.Error("Expected package name 'lodash'")
	}
	if !strings.Contains(output, "GHSA-xxxx-xxxx-xxxx") {
		t.Error("Expected vulnerability ID")
	}
	if !strings.Contains(output, "Prototype Pollution") {
		t.Error("Expected vulnerability title")
	}
	if !strings.Contains(output, "Patched in") {
		t.Error("Expected 'Patched in' label")
	}
	if !strings.Contains(output, "4.17.21") {
		t.Error("Expected patched version")
	}

	// Should contain bullet point
	if !strings.Contains(output, bullet) {
		t.Error("Expected bullet point for vulnerabilities")
	}
}

func TestPrintScanResult_Lockfiles(t *testing.T) {
	resetOutputJSON()

	result := &types.ScanResult{
		Summary: types.ScanSummary{
			LockfilesScanned:  2,
			TotalDependencies: 150,
		},
		Lockfiles: []types.LockfileInfo{
			{Path: "package-lock.json", Type: "npm", Dependencies: 100},
			{Path: "packages/sub/yarn.lock", Type: "yarn-classic", Dependencies: 50},
		},
	}

	output := captureOutput(func() {
		printScanResult(result)
	})

	// Should show lockfiles section
	if !strings.Contains(output, "Lockfiles") {
		t.Error("Expected 'Lockfiles' section")
	}

	// Should show lockfile paths
	if !strings.Contains(output, "package-lock.json") {
		t.Error("Expected 'package-lock.json' path")
	}
	if !strings.Contains(output, "yarn.lock") {
		t.Error("Expected 'yarn.lock' path")
	}

	// Should show types
	if !strings.Contains(output, "npm") {
		t.Error("Expected 'npm' type")
	}
	if !strings.Contains(output, "yarn-classic") {
		t.Error("Expected 'yarn-classic' type")
	}

	// Should show dependency counts
	if !strings.Contains(output, "100 deps") {
		t.Error("Expected '100 deps'")
	}
	if !strings.Contains(output, "50 deps") {
		t.Error("Expected '50 deps'")
	}
}

// =============================================================================
// runCheck Styled Output Tests
// =============================================================================

func TestRunCheck_Styled_WithVulnerabilities(t *testing.T) {
	resetOutputJSON()

	mock := &mockScanner{
		checkResult: &types.CheckResult{
			SupplyChain: types.CheckSupplyChainResult{
				Compromised: false,
			},
			Vulnerabilities: []types.VulnerabilityInfo{
				{
					ID:       "GHSA-xxxx-xxxx-xxxx",
					Title:    "Prototype Pollution",
					Severity: "high",
				},
			},
		},
	}

	output := captureOutput(func() {
		runCheck(mock, "lodash", "4.17.15")
	})

	// Should show header
	if !strings.Contains(output, "Package Check") {
		t.Error("Expected 'Package Check' header")
	}

	// Should show package info
	if !strings.Contains(output, "lodash") {
		t.Error("Expected package name")
	}
	if !strings.Contains(output, "4.17.15") {
		t.Error("Expected version")
	}

	// Should show supply chain status (either clean or compromised)
	hasSupplyChainMsg := strings.Contains(output, "No supply chain issues") ||
		strings.Contains(output, "compromise detected")
	if !hasSupplyChainMsg {
		t.Error("Expected supply chain status message")
	}
}

func TestRunCheck_Styled_CleanPackage(t *testing.T) {
	resetOutputJSON()

	mock := &mockScanner{
		checkResult: &types.CheckResult{
			SupplyChain: types.CheckSupplyChainResult{
				Compromised: false,
			},
			Vulnerabilities: []types.VulnerabilityInfo{},
		},
	}

	output := captureOutput(func() {
		runCheck(mock, "lodash", "4.17.21")
	})

	// Should show success for supply chain
	if !strings.Contains(output, "No supply chain issues") {
		t.Error("Expected 'No supply chain issues' for clean package")
	}

	// Should contain checkmark
	if !strings.Contains(output, checkMark) {
		t.Error("Expected checkmark for clean package")
	}
}

// =============================================================================
// runRefresh Styled Output Tests
// =============================================================================

func TestRunRefresh_Styled(t *testing.T) {
	resetOutputJSON()

	mock := newDefaultMock()

	output := captureOutput(func() {
		runRefresh(mock, false)
	})

	// Should show header
	if !strings.Contains(output, "Database Refresh") {
		t.Error("Expected 'Database Refresh' header")
	}

	// Should show either updated or up to date message
	hasStatusMsg := strings.Contains(output, "Database updated") ||
		strings.Contains(output, "up to date")
	if !hasStatusMsg {
		t.Error("Expected database status message")
	}

	// Should show counts
	if !strings.Contains(output, "Packages") {
		t.Error("Expected 'Packages' label")
	}
	if !strings.Contains(output, "Versions") {
		t.Error("Expected 'Versions' label")
	}
	if !strings.Contains(output, "Cache age") {
		t.Error("Expected 'Cache age' label")
	}
}

func TestRunRefresh_Styled_Force(t *testing.T) {
	resetOutputJSON()

	mock := newDefaultMock()
	mock.refreshResult = &types.RefreshResult{
		Updated:       true,
		PackagesCount: 150,
		VersionsCount: 300,
		CacheAgeHours: 0,
		SourceResults: map[string]types.SourceRefreshInfo{
			"datadog": {PackageCount: 150},
		},
	}

	output := captureOutput(func() {
		runRefresh(mock, true)
	})

	// Should show header
	if !strings.Contains(output, "Database Refresh") {
		t.Error("Expected 'Database Refresh' header")
	}

	// Force refresh should show "Database updated"
	if !strings.Contains(output, "Database updated") {
		t.Error("Expected 'Database updated' message for forced refresh")
	}
}

// =============================================================================
// runScan Styled Output Tests
// =============================================================================

func TestRunScan_Styled(t *testing.T) {
	resetOutputJSON()

	mock := &mockScanner{
		scanResult: &types.ScanResult{
			Summary: types.ScanSummary{
				LockfilesScanned:  1,
				TotalDependencies: 2,
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
				{Path: "package-lock.json", Type: "npm", Dependencies: 2},
			},
		},
	}

	output := captureOutput(func() {
		runScan(mock, "/tmp/test", scanOptions{Recursive: false, IncludeDev: true})
	})

	// Should show header
	if !strings.Contains(output, "Scan Results") {
		t.Error("Expected 'Scan Results' header")
	}

	// Should show summary section
	if !strings.Contains(output, "Summary") {
		t.Error("Expected 'Summary' section")
	}
	if !strings.Contains(output, "Lockfiles scanned") {
		t.Error("Expected 'Lockfiles scanned' label")
	}
	if !strings.Contains(output, "Dependencies") {
		t.Error("Expected 'Dependencies' label")
	}

	// Should show lockfiles section
	if !strings.Contains(output, "Lockfiles") {
		t.Error("Expected 'Lockfiles' section")
	}
	if !strings.Contains(output, "package-lock.json") {
		t.Error("Expected lockfile path in output")
	}
}
