package audit

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/seanhalberthal/supplyscan/internal/types"
)

const (
	testLodashVersion = "4.17.21"
)

func TestNewClient(t *testing.T) {
	client := NewClient()
	if client == nil {
		t.Fatal("NewClient() returned nil")
	}
	if client.httpClient == nil {
		t.Error("httpClient is nil")
	}
	if client.endpoint != defaultEndpoint {
		t.Errorf("endpoint = %q, want %q", client.endpoint, defaultEndpoint)
	}
}

func TestNewClient_WithOptions(t *testing.T) {
	customHTTP := &http.Client{}
	customEndpoint := "https://custom.example.com/audit"

	client := NewClient(
		withHTTPClient(customHTTP),
		withEndpoint(customEndpoint),
	)

	if client.httpClient != customHTTP {
		t.Error("WithHTTPClient option not applied")
	}
	if client.endpoint != customEndpoint {
		t.Errorf("endpoint = %q, want %q", client.endpoint, customEndpoint)
	}
}

func TestBuildAuditRequest(t *testing.T) {
	deps := []types.Dependency{
		{Name: "lodash", Version: testLodashVersion},
		{Name: "@babel/core", Version: "7.23.0"},
	}

	req := buildAuditRequest(deps)

	if req.Name != "audit-check" {
		t.Errorf("Name = %q, want audit-check", req.Name)
	}
	if req.Version != "1.0.0" {
		t.Errorf("Version = %q, want 1.0.0", req.Version)
	}

	// Check requires
	if req.Requires["lodash"] != testLodashVersion {
		t.Errorf("Requires[lodash] = %q, want %s", req.Requires["lodash"], testLodashVersion)
	}
	if req.Requires["@babel/core"] != "7.23.0" {
		t.Errorf("Requires[@babel/core] = %q, want 7.23.0", req.Requires["@babel/core"])
	}

	// Check dependencies
	if req.Dependencies["lodash"].Version != testLodashVersion {
		t.Errorf("Dependencies[lodash].Version = %q, want %s", req.Dependencies["lodash"].Version, testLodashVersion)
	}
}

func TestBuildAuditRequest_Empty(t *testing.T) {
	req := buildAuditRequest([]types.Dependency{})

	if len(req.Requires) != 0 {
		t.Errorf("Expected empty requires, got %d", len(req.Requires))
	}
	if len(req.Dependencies) != 0 {
		t.Errorf("Expected empty dependencies, got %d", len(req.Dependencies))
	}
}

func TestNormaliseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"critical", "critical"},
		{"CRITICAL", "critical"},
		{"Critical", "critical"},
		{"high", "high"},
		{"HIGH", "high"},
		{"moderate", "moderate"},
		{"low", "low"},
		{"info", "info"},
		{"unknown_severity", "unknown"},
		{"", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := normaliseSeverity(tt.input); got != tt.want {
				t.Errorf("normaliseSeverity(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestGetAdvisoryID(t *testing.T) {
	tests := []struct {
		name   string
		adv    advisory
		wantID string
	}{
		{
			name:   "with GHSA ID",
			adv:    advisory{ID: 123, GHSAID: "GHSA-abcd-1234-efgh"},
			wantID: "GHSA-abcd-1234-efgh",
		},
		{
			name:   "without GHSA ID",
			adv:    advisory{ID: 456},
			wantID: "npm:456",
		},
		{
			name:   "empty GHSA ID",
			adv:    advisory{ID: 789, GHSAID: ""},
			wantID: "npm:789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getAdvisoryID(&tt.adv); got != tt.wantID {
				t.Errorf("getAdvisoryID() = %q, want %q", got, tt.wantID)
			}
		})
	}
}

func TestConvertAdvisories(t *testing.T) {
	advisories := map[string]advisory{
		"1001": {
			ID:              1001,
			Title:           "Prototype Pollution",
			ModuleName:      "lodash",
			Severity:        "high",
			PatchedVersions: ">=4.17.21",
			GHSAID:          "GHSA-xxxx-yyyy-zzzz",
			Findings: []finding{
				{Version: "4.17.20", Paths: []string{"lodash"}},
			},
		},
		"1002": {
			ID:              1002,
			Title:           "ReDoS",
			ModuleName:      "minimatch",
			Severity:        "moderate",
			PatchedVersions: ">=3.0.5",
			Findings: []finding{
				{Version: "3.0.4", Paths: []string{"minimatch"}},
				{Version: "3.0.3", Paths: []string{"glob>minimatch"}},
			},
		},
	}

	findings := convertAdvisories(advisories)

	// Should have 3 findings (1 for lodash, 2 for minimatch)
	if len(findings) != 3 {
		t.Errorf("Expected 3 findings, got %d", len(findings))
	}

	// Check lodash finding
	var lodashFinding *types.VulnerabilityFinding
	for i := range findings {
		if findings[i].Package == "lodash" {
			lodashFinding = &findings[i]
			break
		}
	}

	if lodashFinding == nil {
		t.Fatal("Expected finding for lodash")
	}

	if lodashFinding.Severity != "high" {
		t.Errorf("lodash severity = %q, want high", lodashFinding.Severity)
	}
	if lodashFinding.ID != "GHSA-xxxx-yyyy-zzzz" {
		t.Errorf("lodash ID = %q, want GHSA-xxxx-yyyy-zzzz", lodashFinding.ID)
	}
	if lodashFinding.InstalledVersion != "4.17.20" {
		t.Errorf("lodash InstalledVersion = %q, want 4.17.20", lodashFinding.InstalledVersion)
	}
	if lodashFinding.PatchedIn != ">=4.17.21" {
		t.Errorf("lodash PatchedIn = %q, want >=4.17.21", lodashFinding.PatchedIn)
	}
}

func TestConvertAdvisories_NoFindings(t *testing.T) {
	// advisory without specific findings should still be reported
	advisories := map[string]advisory{
		"1001": {
			ID:              1001,
			Title:           "Security Issue",
			ModuleName:      "some-pkg",
			Severity:        "critical",
			PatchedVersions: ">=2.0.0",
			Findings:        []finding{}, // Empty findings
		},
	}

	findings := convertAdvisories(advisories)

	if len(findings) != 1 {
		t.Errorf("Expected 1 finding for advisory without findings, got %d", len(findings))
	}

	if findings[0].Package != "some-pkg" {
		t.Errorf("Package = %q, want some-pkg", findings[0].Package)
	}
	if findings[0].InstalledVersion != "" {
		t.Errorf("InstalledVersion = %q, want empty", findings[0].InstalledVersion)
	}
}

func TestConvertAdvisories_Empty(t *testing.T) {
	findings := convertAdvisories(map[string]advisory{})

	if findings == nil {
		t.Error("Expected empty slice, got nil")
	}
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(findings))
	}
}

func TestAuditDependencies_MockServer(t *testing.T) {
	// Create mock server
	mockResponse := response{
		Advisories: map[string]advisory{
			"1001": {
				ID:              1001,
				Title:           "Test Vulnerability",
				ModuleName:      "test-pkg",
				Severity:        "high",
				PatchedVersions: ">=2.0.0",
				Findings: []finding{
					{Version: "1.0.0", Paths: []string{"test-pkg"}},
				},
			},
		},
		Metadata: metadata{
			Vulnerabilities: vulnerabilityCounts{High: 1},
			Dependencies:    1,
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type: application/json, got %s", r.Header.Get("Content-Type"))
		}

		// Decode request body to verify format
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("Failed to decode request body: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(mockResponse)
		if err != nil {
			fmt.Printf("Failed to encode mock response: %v\n", err)
		}
	}))
	defer server.Close()

	// Create client with mock server endpoint
	client := NewClient(
		withHTTPClient(server.Client()),
		withEndpoint(server.URL),
	)

	deps := []types.Dependency{
		{Name: "test-pkg", Version: "1.0.0"},
	}

	// Test full AuditDependencies flow
	findings, err := client.AuditDependencies(deps)
	if err != nil {
		t.Fatalf("AuditDependencies() error = %v", err)
	}

	if len(findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(findings))
	}

	if findings[0].Package != "test-pkg" {
		t.Errorf("Package = %q, want test-pkg", findings[0].Package)
	}
	if findings[0].Severity != "high" {
		t.Errorf("Severity = %q, want high", findings[0].Severity)
	}
	if findings[0].InstalledVersion != "1.0.0" {
		t.Errorf("InstalledVersion = %q, want 1.0.0", findings[0].InstalledVersion)
	}

	// Test that nil/empty deps return early
	findings, err = client.AuditDependencies(nil)
	if err != nil {
		t.Errorf("AuditDependencies(nil) error = %v", err)
	}
	if findings != nil {
		t.Errorf("AuditDependencies(nil) = %v, want nil", findings)
	}

	findings, err = client.AuditDependencies([]types.Dependency{})
	if err != nil {
		t.Errorf("AuditDependencies([]) error = %v", err)
	}
	if findings != nil {
		t.Errorf("AuditDependencies([]) = %v, want nil", findings)
	}
}

func TestAuditDependencies_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(
		withHTTPClient(server.Client()),
		withEndpoint(server.URL),
	)

	deps := []types.Dependency{
		{Name: "test-pkg", Version: "1.0.0"},
	}

	_, err := client.AuditDependencies(deps)
	if err == nil {
		t.Error("Expected error for server error response")
	}
}

func TestAuditDependencies_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	client := NewClient(
		withHTTPClient(server.Client()),
		withEndpoint(server.URL),
	)

	deps := []types.Dependency{
		{Name: "test-pkg", Version: "1.0.0"},
	}

	_, err := client.AuditDependencies(deps)
	if err == nil {
		t.Error("Expected error for invalid JSON response")
	}
}

func TestAuditSinglePackage_MockServer(t *testing.T) {
	mockResponse := response{
		Advisories: map[string]advisory{
			"1001": {
				ID:              1001,
				Title:           "Prototype Pollution",
				ModuleName:      "lodash",
				Severity:        "high",
				PatchedVersions: ">=4.17.21",
				GHSAID:          "GHSA-test-1234",
				Findings: []finding{
					{Version: "4.17.20", Paths: []string{"lodash"}},
				},
			},
		},
		Metadata: metadata{
			Vulnerabilities: vulnerabilityCounts{High: 1},
			Dependencies:    1,
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	client := NewClient(
		withHTTPClient(server.Client()),
		withEndpoint(server.URL),
	)

	vulns, err := client.AuditSinglePackage("lodash", "4.17.20")
	if err != nil {
		t.Fatalf("AuditSinglePackage() error = %v", err)
	}

	if len(vulns) != 1 {
		t.Errorf("Expected 1 vulnerability, got %d", len(vulns))
	}

	if vulns[0].ID != "GHSA-test-1234" {
		t.Errorf("ID = %q, want GHSA-test-1234", vulns[0].ID)
	}
	if vulns[0].Severity != "high" {
		t.Errorf("Severity = %q, want high", vulns[0].Severity)
	}
	if vulns[0].Title != "Prototype Pollution" {
		t.Errorf("Title = %q, want Prototype Pollution", vulns[0].Title)
	}
	if vulns[0].PatchedIn != ">=4.17.21" {
		t.Errorf("PatchedIn = %q, want >=4.17.21", vulns[0].PatchedIn)
	}
}

func TestAuditSinglePackage_NoVulnerabilities(t *testing.T) {
	mockResponse := response{
		Advisories: map[string]advisory{},
		Metadata: metadata{
			Dependencies: 1,
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	client := NewClient(
		withHTTPClient(server.Client()),
		withEndpoint(server.URL),
	)

	vulns, err := client.AuditSinglePackage("safe-pkg", "1.0.0")
	if err != nil {
		t.Fatalf("AuditSinglePackage() error = %v", err)
	}

	if vulns == nil {
		t.Error("Expected empty slice, got nil")
	}
	if len(vulns) != 0 {
		t.Errorf("Expected 0 vulnerabilities, got %d", len(vulns))
	}
}

func TestRequest_JSONMarshaling(t *testing.T) {
	req := &request{
		Name:    "test",
		Version: "1.0.0",
		Requires: map[string]string{
			"lodash": "4.17.21",
		},
		Dependencies: map[string]dep{
			"lodash": {Version: "4.17.21"},
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var parsed request
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if parsed.Name != "test" {
		t.Errorf("Name = %q, want test", parsed.Name)
	}
	if parsed.Requires["lodash"] != "4.17.21" {
		t.Errorf("Requires[lodash] = %q, want 4.17.21", parsed.Requires["lodash"])
	}
}

func TestResponse_JSONUnmarshaling(t *testing.T) {
	jsonData := `{
		"advisories": {
			"1001": {
				"id": 1001,
				"title": "Test Vuln",
				"module_name": "test-pkg",
				"severity": "high",
				"vulnerable_versions": "<2.0.0",
				"patched_versions": ">=2.0.0",
				"github_advisory_id": "GHSA-test-1234",
				"cwe": ["CWE-79"],
				"findings": [
					{"version": "1.0.0", "paths": ["test-pkg"]}
				]
			}
		},
		"metadata": {
			"vulnerabilities": {
				"info": 0,
				"low": 0,
				"moderate": 0,
				"high": 1,
				"critical": 0
			},
			"dependencies": 10
		}
	}`

	var resp response
	if err := json.Unmarshal([]byte(jsonData), &resp); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if len(resp.Advisories) != 1 {
		t.Errorf("Expected 1 advisory, got %d", len(resp.Advisories))
	}

	adv := resp.Advisories["1001"]
	if adv.ID != 1001 {
		t.Errorf("advisory ID = %d, want 1001", adv.ID)
	}
	if adv.GHSAID != "GHSA-test-1234" {
		t.Errorf("GHSAID = %q, want GHSA-test-1234", adv.GHSAID)
	}
	if len(adv.CWE) != 1 || adv.CWE[0] != "CWE-79" {
		t.Errorf("CWE = %v, want [CWE-79]", adv.CWE)
	}
	if len(adv.Findings) != 1 {
		t.Errorf("Findings = %d, want 1", len(adv.Findings))
	}
	if resp.Metadata.Vulnerabilities.High != 1 {
		t.Errorf("High vulns = %d, want 1", resp.Metadata.Vulnerabilities.High)
	}
}

func TestDoAudit_InvalidEndpoint(t *testing.T) {
	// Create a client with a short timeout
	c := &Client{
		httpClient: &http.Client{},
	}

	// Build a request
	req := buildAuditRequest([]types.Dependency{
		{Name: "test", Version: "1.0.0"},
	})

	// This will fail because we can't connect to the real endpoint in tests
	// The important thing is it handles errors gracefully
	_, err := c.doAudit(req)
	// We expect an error since we're not mocking the real endpoint
	if err == nil {
		t.Log("doAudit() succeeded unexpectedly (real npm API available)")
	}
}

func TestVulnerabilityCounts_JSONUnmarshaling(t *testing.T) {
	jsonData := `{
		"info": 1,
		"low": 2,
		"moderate": 3,
		"high": 4,
		"critical": 5
	}`

	var counts vulnerabilityCounts
	if err := json.Unmarshal([]byte(jsonData), &counts); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if counts.Info != 1 {
		t.Errorf("Info = %d, want 1", counts.Info)
	}
	if counts.Low != 2 {
		t.Errorf("Low = %d, want 2", counts.Low)
	}
	if counts.Moderate != 3 {
		t.Errorf("Moderate = %d, want 3", counts.Moderate)
	}
	if counts.High != 4 {
		t.Errorf("High = %d, want 4", counts.High)
	}
	if counts.Critical != 5 {
		t.Errorf("Critical = %d, want 5", counts.Critical)
	}
}

func TestDep_JSONMarshaling(t *testing.T) {
	d := dep{
		Version:  "1.0.0",
		Requires: map[string]string{"other": "2.0.0"},
	}

	data, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var parsed dep
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if parsed.Version != "1.0.0" {
		t.Errorf("Version = %q, want 1.0.0", parsed.Version)
	}
	if parsed.Requires["other"] != "2.0.0" {
		t.Errorf("Requires[other] = %q, want 2.0.0", parsed.Requires["other"])
	}
}

func TestDep_OmitsEmptyRequires(t *testing.T) {
	d := dep{
		Version:  "1.0.0",
		Requires: nil,
	}

	data, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	// Should not contain "requires" key when nil
	if string(data) != `{"version":"1.0.0"}` {
		t.Errorf("JSON = %s, want without requires", string(data))
	}
}

func BenchmarkBuildAuditRequest(b *testing.B) {
	deps := make([]types.Dependency, 100)
	for i := 0; i < 100; i++ {
		deps[i] = types.Dependency{
			Name:    "pkg-" + string(rune('a'+i%26)),
			Version: "1.0.0",
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buildAuditRequest(deps)
	}
}

func BenchmarkConvertAdvisories(b *testing.B) {
	advisories := make(map[string]advisory)
	for i := 0; i < 50; i++ {
		advisories[string(rune('0'+i))] = advisory{
			ID:         i,
			Title:      "Test Vulnerability",
			ModuleName: "test-pkg",
			Severity:   "high",
			Findings: []finding{
				{Version: "1.0.0"},
				{Version: "1.0.1"},
			},
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		convertAdvisories(advisories)
	}
}
