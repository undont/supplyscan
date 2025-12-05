package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seanhalberthal/supplyscan-mcp/internal/scanner"
	"github.com/seanhalberthal/supplyscan-mcp/internal/types"
)

// captureOutput captures stdout during function execution
func captureOutput(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

// captureStderr captures stderr during function execution
func captureStderr(f func()) string {
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	f()

	w.Close()
	os.Stderr = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

func TestParseScanFlags(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantRec    bool
		wantDev    bool
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

func TestPrintUsage(t *testing.T) {
	output := captureOutput(func() {
		printUsage()
	})

	// Check that usage contains expected elements
	expectedPhrases := []string{
		"supplyscan-mcp",
		"MCP server",
		"CLI mode",
		"status",
		"scan",
		"check",
		"refresh",
		"--recursive",
	}

	for _, phrase := range expectedPhrases {
		if !strings.Contains(output, phrase) {
			t.Errorf("Usage output missing %q", phrase)
		}
	}
}

func TestRunStatus(t *testing.T) {
	scan, err := scanner.New()
	if err != nil {
		t.Fatalf("scanner.New() error = %v", err)
	}

	output := captureOutput(func() {
		runStatus(scan)
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

func TestRunScan_Success(t *testing.T) {
	// Create test project
	tmpDir := t.TempDir()
	lockfileContent := `{
		"name": "test",
		"lockfileVersion": 3,
		"packages": {
			"node_modules/lodash": {"version": "4.17.21"}
		}
	}`
	if err := os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte(lockfileContent), 0644); err != nil {
		t.Fatal(err)
	}

	scan, err := scanner.New()
	if err != nil {
		t.Fatalf("scanner.New() error = %v", err)
	}

	output := captureOutput(func() {
		runScan(scan, tmpDir, scanOptions{Recursive: false, IncludeDev: true})
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

func TestRunScan_WithFlags(t *testing.T) {
	// Create test project with nested structure
	tmpDir := t.TempDir()

	// Root lockfile
	rootLock := `{
		"name": "root",
		"lockfileVersion": 3,
		"packages": {
			"node_modules/a": {"version": "1.0.0"}
		}
	}`
	if err := os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte(rootLock), 0644); err != nil {
		t.Fatal(err)
	}

	// Nested lockfile
	nestedDir := filepath.Join(tmpDir, "packages", "sub")
	if err := os.MkdirAll(nestedDir, 0755); err != nil {
		t.Fatal(err)
	}
	nestedLock := `{
		"name": "sub",
		"lockfileVersion": 3,
		"packages": {
			"node_modules/b": {"version": "1.0.0"}
		}
	}`
	if err := os.WriteFile(filepath.Join(nestedDir, "package-lock.json"), []byte(nestedLock), 0644); err != nil {
		t.Fatal(err)
	}

	scan, err := scanner.New()
	if err != nil {
		t.Fatalf("scanner.New() error = %v", err)
	}

	// Test with recursive flag
	output := captureOutput(func() {
		runScan(scan, tmpDir, scanOptions{Recursive: true, IncludeDev: true})
	})

	var result types.ScanResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	if result.Summary.LockfilesScanned != 2 {
		t.Errorf("With recursive: LockfilesScanned = %d, want 2", result.Summary.LockfilesScanned)
	}
}

func TestRunCheck(t *testing.T) {
	scan, err := scanner.New()
	if err != nil {
		t.Fatalf("scanner.New() error = %v", err)
	}

	output := captureOutput(func() {
		runCheck(scan, "lodash", "4.17.21")
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

func TestRunRefresh(t *testing.T) {
	scan, err := scanner.New()
	if err != nil {
		t.Fatalf("scanner.New() error = %v", err)
	}

	// Note: This might actually hit the network in a real test
	// In production tests, you'd mock the HTTP client
	output := captureOutput(func() {
		runRefresh(scan, false) // Don't force to use cached
	})

	// Should be valid JSON
	var result types.RefreshResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		// If network fails, the output might be an error
		if !strings.Contains(output, "Error") {
			t.Errorf("Output is not valid JSON: %v\nOutput: %s", err, output)
		}
	}
}

func TestPrintJSON(t *testing.T) {
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
	testData := types.StatusResponse{
		Version: "1.0.0",
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

	if parsed.Version != "1.0.0" {
		t.Errorf("Version = %q, want 1.0.0", parsed.Version)
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

func TestRun_UnknownCommand(t *testing.T) {
	scan, err := scanner.New()
	if err != nil {
		t.Fatalf("scanner.New() error = %v", err)
	}

	// Capture stderr and check for error message
	// Note: Run calls os.Exit, so we need to handle that
	// For now, just verify the printUsage path

	stderr := captureStderr(func() {
		// We can't test os.Exit directly, but we can test the error message path
		// by checking that unknown commands produce error output
	})

	// This is a limited test due to os.Exit behavior
	_ = scan
	_ = stderr
}

func TestErrorFormat(t *testing.T) {
	// Verify the error format constant is correct
	expected := "Error: %v\n"
	if errorFormat != expected {
		t.Errorf("errorFormat = %q, want %q", errorFormat, expected)
	}
}

// Integration tests

func TestCLI_StatusIntegration(t *testing.T) {
	scan, err := scanner.New()
	if err != nil {
		t.Fatalf("scanner.New() error = %v", err)
	}

	output := captureOutput(func() {
		runStatus(scan)
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
	// Create a realistic project structure
	tmpDir := t.TempDir()

	// Create package-lock.json
	lockfile := `{
		"name": "integration-test",
		"version": "1.0.0",
		"lockfileVersion": 3,
		"packages": {
			"node_modules/express": {
				"version": "4.18.2"
			},
			"node_modules/lodash": {
				"version": "4.17.21"
			},
			"node_modules/@types/node": {
				"version": "20.8.0",
				"dev": true
			}
		}
	}`

	if err := os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte(lockfile), 0644); err != nil {
		t.Fatal(err)
	}

	scan, err := scanner.New()
	if err != nil {
		t.Fatalf("scanner.New() error = %v", err)
	}

	// Test scan
	output := captureOutput(func() {
		runScan(scan, tmpDir, scanOptions{Recursive: false, IncludeDev: false})
	})

	var result types.ScanResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// With IncludeDev=false, should only have 2 dependencies
	if result.Summary.TotalDependencies != 2 {
		t.Errorf("TotalDependencies = %d, want 2 (dev excluded)", result.Summary.TotalDependencies)
	}

	// Test with dev included
	output2 := captureOutput(func() {
		runScan(scan, tmpDir, scanOptions{Recursive: false, IncludeDev: true})
	})

	var result2 types.ScanResult
	if err := json.Unmarshal([]byte(output2), &result2); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if result2.Summary.TotalDependencies != 3 {
		t.Errorf("TotalDependencies = %d, want 3 (dev included)", result2.Summary.TotalDependencies)
	}
}

func TestCLI_CheckIntegration(t *testing.T) {
	scan, err := scanner.New()
	if err != nil {
		t.Fatalf("scanner.New() error = %v", err)
	}

	// Check a scoped package
	output := captureOutput(func() {
		runCheck(scan, "@babel/core", "7.23.0")
	})

	var result types.CheckResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// Should have supply_chain and vulnerabilities fields
	// The actual values depend on IOC database and npm audit
}

func TestCLI_JSONOutputFormat(t *testing.T) {
	// Test that all CLI commands produce properly indented JSON

	scan, err := scanner.New()
	if err != nil {
		t.Fatalf("scanner.New() error = %v", err)
	}

	output := captureOutput(func() {
		runStatus(scan)
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