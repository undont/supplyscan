package audit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	semver "github.com/Masterminds/semver/v3"

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
	if client.httpClient.Timeout != defaultTimeout {
		t.Errorf("httpClient.Timeout = %v, want %v", client.httpClient.Timeout, defaultTimeout)
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

func TestBuildBulkRequest(t *testing.T) {
	deps := []types.Dependency{
		{Name: "lodash", Version: testLodashVersion},
		{Name: "@babel/core", Version: "7.23.0"},
	}

	req := buildBulkRequest(deps)

	// Check that both packages are in the request
	if len(req) != 2 {
		t.Errorf("Expected 2 packages in request, got %d", len(req))
	}

	lodashVersions := req["lodash"]
	if len(lodashVersions) != 1 || lodashVersions[0] != testLodashVersion {
		t.Errorf("lodash versions = %v, want [%s]", lodashVersions, testLodashVersion)
	}

	babelVersions := req["@babel/core"]
	if len(babelVersions) != 1 || babelVersions[0] != "7.23.0" {
		t.Errorf("@babel/core versions = %v, want [7.23.0]", babelVersions)
	}
}

func TestBuildBulkRequest_MultipleVersions(t *testing.T) {
	deps := []types.Dependency{
		{Name: "lodash", Version: "4.17.20"},
		{Name: "lodash", Version: "4.17.21"},
	}

	req := buildBulkRequest(deps)

	if len(req) != 1 {
		t.Errorf("Expected 1 package in request, got %d", len(req))
	}

	versions := req["lodash"]
	if len(versions) != 2 {
		t.Errorf("Expected 2 versions, got %d", len(versions))
	}
}

func TestBuildBulkRequest_Empty(t *testing.T) {
	req := buildBulkRequest([]types.Dependency{})

	if len(req) != 0 {
		t.Errorf("Expected empty request, got %d packages", len(req))
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

func TestGetBulkAdvisoryID(t *testing.T) {
	tests := []struct {
		name   string
		adv    bulkAdvisory
		wantID string
	}{
		{
			name:   "with GHSA ID",
			adv:    bulkAdvisory{ID: 123, GHSAID: "GHSA-abcd-1234-efgh"},
			wantID: "GHSA-abcd-1234-efgh",
		},
		{
			name:   "without GHSA ID",
			adv:    bulkAdvisory{ID: 456},
			wantID: "npm:456",
		},
		{
			name:   "empty GHSA ID",
			adv:    bulkAdvisory{ID: 789, GHSAID: ""},
			wantID: "npm:789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getBulkAdvisoryID(&tt.adv); got != tt.wantID {
				t.Errorf("getBulkAdvisoryID() = %q, want %q", got, tt.wantID)
			}
		})
	}
}

func TestConvertBulkAdvisories(t *testing.T) {
	resp := bulkResponse{
		"lodash": {
			{
				ID:                 1001,
				Title:              "Prototype Pollution",
				Severity:           "high",
				VulnerableVersions: "<4.17.21",
				PatchedVersions:    ">=4.17.21",
				GHSAID:             "GHSA-xxxx-yyyy-zzzz",
			},
		},
		"minimatch": {
			{
				ID:                 1002,
				Title:              "ReDoS",
				Severity:           "moderate",
				VulnerableVersions: "<3.0.5",
				PatchedVersions:    ">=3.0.5",
			},
		},
	}

	deps := []types.Dependency{
		{Name: "lodash", Version: "4.17.20"},
		{Name: "minimatch", Version: "3.0.4"},
		{Name: "minimatch", Version: "3.0.3"},
	}

	findings := convertBulkAdvisories(resp, deps)

	// Should have 3 findings (1 for lodash, 2 for minimatch since 2 installed versions)
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

func TestConvertBulkAdvisories_ExcludesPatchedVersions(t *testing.T) {
	resp := bulkResponse{
		"minimatch": {
			{
				ID:                 1084,
				Title:              "ReDoS vulnerability",
				Severity:           "high",
				VulnerableVersions: "<3.1.3 || >=4.0.0 <5.1.7",
				PatchedVersions:    ">=3.1.3 <4.0.0 || >=5.1.7",
				GHSAID:             "GHSA-3ppc-4f35-3m26",
			},
		},
	}

	deps := []types.Dependency{
		{Name: "minimatch", Version: "3.0.4"}, // vulnerable
		{Name: "minimatch", Version: "3.1.3"}, // patched
		{Name: "minimatch", Version: "5.1.6"}, // vulnerable
		{Name: "minimatch", Version: "5.1.7"}, // patched
		{Name: "minimatch", Version: "9.0.6"}, // not in vulnerable range
	}

	findings := convertBulkAdvisories(resp, deps)

	// Only 3.0.4 and 5.1.6 should be flagged; 3.1.3, 5.1.7, and 9.0.6 are not vulnerable
	vulnerableVersions := make(map[string]bool)
	for _, f := range findings {
		vulnerableVersions[f.InstalledVersion] = true
	}

	if !vulnerableVersions["3.0.4"] {
		t.Error("Expected 3.0.4 to be flagged as vulnerable")
	}
	if !vulnerableVersions["5.1.6"] {
		t.Error("Expected 5.1.6 to be flagged as vulnerable")
	}
	if vulnerableVersions["3.1.3"] {
		t.Error("3.1.3 should NOT be flagged (it is the patched version)")
	}
	if vulnerableVersions["5.1.7"] {
		t.Error("5.1.7 should NOT be flagged (it is the patched version)")
	}
	if vulnerableVersions["9.0.6"] {
		t.Error("9.0.6 should NOT be flagged (not in vulnerable range)")
	}
	if len(findings) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(findings))
	}
}

func TestParseVulnerableRange(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantNil bool
	}{
		{"empty string returns nil", "", true},
		{"simple less-than", "<3.1.3", false},
		{"simple greater-or-equal", ">=2.0.0", false},
		{"compound OR range", "<3.1.3 || >=4.0.0 <5.1.7", false},
		{"single version constraint", "1.0.0", false},
		{"malformed range returns nil", ">=abc", true},
		{"incomplete operator returns nil", "<", true},
		{"nonsense string returns nil", "not-a-range", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := parseVulnerableRange(tt.input)
			if tt.wantNil && c != nil {
				t.Errorf("parseVulnerableRange(%q) = non-nil, want nil", tt.input)
			}
			if !tt.wantNil && c == nil {
				t.Errorf("parseVulnerableRange(%q) = nil, want constraint", tt.input)
			}
		})
	}
}

func TestIsVersionVulnerable(t *testing.T) {
	lessThan3 := mustConstraint(t, "<3.0.5")
	compoundOR := mustConstraint(t, "<3.1.3 || >=4.0.0 <5.1.7")

	tests := []struct {
		name       string
		version    string
		constraint *semver.Constraints
		want       bool
	}{
		// nil constraint fallback (safe default)
		{"nil constraint returns true", "1.0.0", nil, true},
		{"nil constraint with any version", "99.99.99", nil, true},

		// unparseable version fallback (safe default)
		{"unparseable version returns true", "latest", lessThan3, true},
		{"non-semver version returns true", "linked", lessThan3, true},
		{"empty version returns true", "", lessThan3, true},

		// simple range matching
		{"vulnerable version matches", "3.0.4", lessThan3, true},
		{"patched version does not match", "3.0.5", lessThan3, false},
		{"version above range does not match", "4.0.0", lessThan3, false},

		// compound OR range
		{"first OR branch vulnerable", "3.0.4", compoundOR, true},
		{"first OR branch patched", "3.1.3", compoundOR, false},
		{"second OR branch vulnerable", "5.1.6", compoundOR, true},
		{"second OR branch patched", "5.1.7", compoundOR, false},
		{"above all ranges", "9.0.6", compoundOR, false},

		// pre-release versions — Masterminds/semver does not match pre-release
		// against constraints without pre-release tags (standard SemVer behaviour)
		{"pre-release not matched by simple range", "3.0.5-alpha.1", lessThan3, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isVersionVulnerable(tt.version, tt.constraint)
			if got != tt.want {
				t.Errorf("isVersionVulnerable(%q, constraint) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

// mustConstraint is a test helper that parses a semver constraint or fails the test.
func mustConstraint(t *testing.T, s string) *semver.Constraints {
	t.Helper()
	c, err := semver.NewConstraint(s)
	if err != nil {
		t.Fatalf("failed to parse constraint %q: %v", s, err)
	}
	return c
}

func TestConvertBulkAdvisories_NilVulnerableVersionsFallback(t *testing.T) {
	// When VulnerableVersions is empty, the nil-constraint fallback should report
	// all installed versions as vulnerable (safe default)
	resp := bulkResponse{
		"test-pkg": {
			{
				ID:              1001,
				Title:           "Test Vulnerability",
				Severity:        "high",
				PatchedVersions: ">=2.0.0",
				// VulnerableVersions intentionally empty
			},
		},
	}

	deps := []types.Dependency{
		{Name: "test-pkg", Version: "1.0.0"},
		{Name: "test-pkg", Version: "2.0.0"},
	}

	findings := convertBulkAdvisories(resp, deps)

	// Both versions should be reported because VulnerableVersions is empty (nil fallback)
	if len(findings) != 2 {
		t.Errorf("Expected 2 findings (nil fallback reports all versions), got %d", len(findings))
	}
}

func TestConvertBulkAdvisories_Empty(t *testing.T) {
	findings := convertBulkAdvisories(bulkResponse{}, []types.Dependency{})

	if findings == nil {
		t.Error("Expected empty slice, got nil")
	}
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(findings))
	}
}

func TestAuditDependencies_MockServer(t *testing.T) {
	// Create mock bulk advisory response
	mockResponse := bulkResponse{
		"test-pkg": {
			{
				ID:              1001,
				Title:           "Test Vulnerability",
				Severity:        "high",
				PatchedVersions: ">=2.0.0",
			},
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

		// Decode request body to verify bulk format
		var req bulkRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("Failed to decode request body: %v", err)
		}

		// Verify bulk format: package name -> versions
		if versions, ok := req["test-pkg"]; !ok || len(versions) != 1 || versions[0] != "1.0.0" {
			t.Errorf("Expected bulk request with test-pkg: [1.0.0], got %v", req)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockResponse)
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
	mockResponse := bulkResponse{
		"lodash": {
			{
				ID:              1001,
				Title:           "Prototype Pollution",
				Severity:        "high",
				PatchedVersions: ">=4.17.21",
				GHSAID:          "GHSA-test-1234",
			},
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
	mockResponse := bulkResponse{}

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

func TestBulkRequest_JSONMarshaling(t *testing.T) {
	req := bulkRequest{
		"lodash": {"4.17.21"},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var parsed bulkRequest
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if len(parsed["lodash"]) != 1 || parsed["lodash"][0] != "4.17.21" {
		t.Errorf("lodash versions = %v, want [4.17.21]", parsed["lodash"])
	}
}

func TestBulkResponse_JSONUnmarshaling(t *testing.T) {
	jsonData := `{
		"test-pkg": [
			{
				"id": 1001,
				"url": "https://github.com/advisories/GHSA-test-1234",
				"title": "Test Vuln",
				"severity": "high",
				"vulnerable_versions": "<2.0.0",
				"patched_versions": ">=2.0.0",
				"range": "<2.0.0",
				"github_advisory_id": "GHSA-test-1234",
				"cwe": ["CWE-79"]
			}
		]
	}`

	var resp bulkResponse
	if err := json.Unmarshal([]byte(jsonData), &resp); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	advisories := resp["test-pkg"]
	if len(advisories) != 1 {
		t.Errorf("Expected 1 advisory for test-pkg, got %d", len(advisories))
	}

	adv := advisories[0]
	if adv.ID != 1001 {
		t.Errorf("advisory ID = %d, want 1001", adv.ID)
	}
	if adv.GHSAID != "GHSA-test-1234" {
		t.Errorf("GHSAID = %q, want GHSA-test-1234", adv.GHSAID)
	}
	if len(adv.CWE) != 1 || adv.CWE[0] != "CWE-79" {
		t.Errorf("CWE = %v, want [CWE-79]", adv.CWE)
	}
	if adv.PatchedVersions != ">=2.0.0" {
		t.Errorf("PatchedVersions = %q, want >=2.0.0", adv.PatchedVersions)
	}
}

func TestDoBulkAudit_InvalidEndpoint(t *testing.T) {
	// Create a client without a valid endpoint
	c := &Client{
		httpClient: &http.Client{},
	}

	req := buildBulkRequest([]types.Dependency{
		{Name: "test", Version: "1.0.0"},
	})

	_, err := c.doBulkAudit(req, []types.Dependency{{Name: "test", Version: "1.0.0"}})
	if err == nil {
		t.Log("doBulkAudit() succeeded unexpectedly (real npm API available)")
	}
}

func TestDefaultEndpoint_IsBulkAPI(t *testing.T) {
	// Ensure we're using the bulk advisory endpoint, not the legacy audit endpoint
	expected := "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk"
	if defaultEndpoint != expected {
		t.Errorf("defaultEndpoint = %q, want %q (bulk advisory API)", defaultEndpoint, expected)
	}
}

func BenchmarkBuildBulkRequest(b *testing.B) {
	deps := make([]types.Dependency, 100)
	for i := 0; i < 100; i++ {
		deps[i] = types.Dependency{
			Name:    "pkg-" + string(rune('a'+i%26)),
			Version: "1.0.0",
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buildBulkRequest(deps)
	}
}

func BenchmarkConvertBulkAdvisories(b *testing.B) {
	resp := make(bulkResponse)
	deps := make([]types.Dependency, 0, 50)
	for i := 0; i < 50; i++ {
		name := "test-pkg-" + string(rune('a'+i%26))
		resp[name] = []bulkAdvisory{
			{
				ID:                 i,
				Title:              "Test Vulnerability",
				Severity:           "high",
				VulnerableVersions: "<2.0.0",
				PatchedVersions:    ">=2.0.0",
			},
		}
		deps = append(deps, types.Dependency{Name: name, Version: "1.0.0"})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		convertBulkAdvisories(resp, deps)
	}
}
