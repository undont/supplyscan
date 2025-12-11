package sources

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGitHubAdvisorySource_Name(t *testing.T) {
	src := NewGitHubAdvisorySource()
	if got := src.Name(); got != "github" {
		t.Errorf("Name() = %q, want %q", got, "github")
	}
}

func TestGitHubAdvisorySource_CacheTTL(t *testing.T) {
	src := NewGitHubAdvisorySource()
	if got := src.CacheTTL(); got != gitHubCacheTTL {
		t.Errorf("CacheTTL() = %v, want %v", got, gitHubCacheTTL)
	}
}

func TestGitHubAdvisorySource_WithOptions(t *testing.T) {
	customURL := "https://example.com/advisories"
	customToken := "ghp_test_token"

	src := NewGitHubAdvisorySource(
		withGitHubURL(customURL),
		withGitHubToken(customToken),
	)

	if src.url != customURL {
		t.Errorf("url = %q, want %q", src.url, customURL)
	}
	if src.token != customToken {
		t.Errorf("token = %q, want %q", src.token, customToken)
	}
}

func TestGitHubAdvisorySource_Fetch_Success(t *testing.T) {
	advisories := []gitHubAdvisory{
		{
			GHSAID:   "GHSA-1234-5678-9012",
			Severity: "critical",
			Type:     "malware",
			Vulnerabilities: []gitHubVulnerability{
				{
					Package:                gitHubPackage{Ecosystem: "npm", Name: "malicious-pkg"},
					VulnerableVersionRange: "= 1.0.0",
				},
			},
		},
		{
			GHSAID:   "GHSA-abcd-efgh-ijkl",
			Severity: "high",
			Type:     "malware",
			Vulnerabilities: []gitHubVulnerability{
				{
					Package:                gitHubPackage{Ecosystem: "npm", Name: "@evil/scoped"},
					VulnerableVersionRange: "= 2.0.0, = 2.0.1",
				},
			},
		},
		{
			// Non-npm advisory should be ignored
			GHSAID:   "GHSA-xxxx-yyyy-zzzz",
			Severity: "high",
			Type:     "malware",
			Vulnerabilities: []gitHubVulnerability{
				{
					Package:                gitHubPackage{Ecosystem: "pip", Name: "python-malware"},
					VulnerableVersionRange: "= 1.0.0",
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request headers
		if r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Errorf("Accept header = %q, want %q", r.Header.Get("Accept"), "application/vnd.github+json")
		}
		if r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
			t.Errorf("X-GitHub-Api-Version header = %q, want %q", r.Header.Get("X-GitHub-Api-Version"), "2022-11-28")
		}

		// Verify query parameters
		if r.URL.Query().Get("ecosystem") != "npm" {
			t.Errorf("ecosystem param = %q, want %q", r.URL.Query().Get("ecosystem"), "npm")
		}
		if r.URL.Query().Get("type") != "malware" {
			t.Errorf("type param = %q, want %q", r.URL.Query().Get("type"), "malware")
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(advisories)
	}))
	defer server.Close()

	src := NewGitHubAdvisorySource(withGitHubURL(server.URL))
	ctx := context.Background()

	data, err := src.Fetch(ctx, server.Client())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if data == nil {
		t.Fatal("Fetch() returned nil data")
	}

	if data.Source != "github" {
		t.Errorf("Source = %q, want %q", data.Source, "github")
	}

	if data.Campaign != gitHubCampaign {
		t.Errorf("Campaign = %q, want %q", data.Campaign, gitHubCampaign)
	}

	// Should have 2 packages (npm only, python excluded)
	if len(data.Packages) != 2 {
		t.Errorf("len(Packages) = %d, want 2", len(data.Packages))
	}

	// Check malicious-pkg
	if pkg, ok := data.Packages["malicious-pkg"]; !ok {
		t.Error("Packages missing 'malicious-pkg'")
	} else {
		if pkg.AdvisoryID != "GHSA-1234-5678-9012" {
			t.Errorf("malicious-pkg AdvisoryID = %q, want %q", pkg.AdvisoryID, "GHSA-1234-5678-9012")
		}
		if pkg.Severity != "critical" {
			t.Errorf("malicious-pkg Severity = %q, want %q", pkg.Severity, "critical")
		}
	}

	// Check scoped package
	if pkg, ok := data.Packages["@evil/scoped"]; !ok {
		t.Error("Packages missing '@evil/scoped'")
	} else if len(pkg.Versions) != 2 {
		t.Errorf("@evil/scoped versions = %v, want 2 versions", pkg.Versions)
	}
}

func TestGitHubAdvisorySource_Fetch_WithToken(t *testing.T) {
	testToken := "ghp_test_token_123"
	var receivedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[]"))
	}))
	defer server.Close()

	src := NewGitHubAdvisorySource(
		withGitHubURL(server.URL),
		withGitHubToken("ghp_test_token_123"),
	)
	ctx := context.Background()

	_, err := src.Fetch(ctx, server.Client())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	expectedAuth := "Bearer " + testToken
	if receivedAuth != expectedAuth {
		t.Errorf("Authorization header = %q, want %q", receivedAuth, expectedAuth)
	}
}

func TestGitHubAdvisorySource_Fetch_RateLimit(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"forbidden", http.StatusForbidden},
		{"too many requests", http.StatusTooManyRequests},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			src := NewGitHubAdvisorySource(withGitHubURL(server.URL))
			ctx := context.Background()

			_, err := src.Fetch(ctx, server.Client())
			if err == nil {
				t.Error("Fetch() expected error for rate limiting")
			}
		})
	}
}

func TestGitHubAdvisorySource_Fetch_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	src := NewGitHubAdvisorySource(withGitHubURL(server.URL))
	ctx := context.Background()

	_, err := src.Fetch(ctx, server.Client())
	if err == nil {
		t.Error("Fetch() expected error for server error")
	}
}

func TestGitHubAdvisorySource_Fetch_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	src := NewGitHubAdvisorySource(withGitHubURL(server.URL))
	ctx := context.Background()

	_, err := src.Fetch(ctx, server.Client())
	if err == nil {
		t.Error("Fetch() expected error for invalid JSON")
	}
}

func TestGitHubAdvisorySource_Fetch_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[]"))
	}))
	defer server.Close()

	src := NewGitHubAdvisorySource(withGitHubURL(server.URL))
	ctx := context.Background()

	data, err := src.Fetch(ctx, server.Client())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if len(data.Packages) != 0 {
		t.Errorf("len(Packages) = %d, want 0", len(data.Packages))
	}
}

func TestGitHubAdvisorySource_Fetch_ContextCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	src := NewGitHubAdvisorySource(withGitHubURL(server.URL))
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := src.Fetch(ctx, server.Client())
	if err == nil {
		t.Error("Fetch() expected error for cancelled context")
	}
}

func TestParseVersionRange(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"= 1.0.0", []string{"1.0.0"}},
		{"= 1.0.0, = 1.0.1", []string{"1.0.0", "1.0.1"}},
		{"= 1.0.0, = 2.0.0, = 3.0.0", []string{"1.0.0", "2.0.0", "3.0.0"}},
		{">= 0", []string{">= 0"}},
		{"", nil},
		{"  = 1.0.0  ", []string{"1.0.0"}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseVersionRange(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("parseVersionRange(%q) = %v, want %v", tt.input, got, tt.want)
				return
			}
			for i, v := range got {
				if v != tt.want[i] {
					t.Errorf("parseVersionRange(%q)[%d] = %q, want %q", tt.input, i, v, tt.want[i])
				}
			}
		})
	}
}

func TestMergeVersionRanges(t *testing.T) {
	tests := []struct {
		name     string
		existing []string
		newRange string
		want     int
	}{
		{"add new version", []string{"1.0.0"}, "= 2.0.0", 2},
		{"duplicate version", []string{"1.0.0"}, "= 1.0.0", 1},
		{"multiple new", []string{"1.0.0"}, "= 2.0.0, = 3.0.0", 3},
		{"empty existing", nil, "= 1.0.0", 1},
		{"empty new", []string{"1.0.0"}, "", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeVersionRanges(tt.existing, tt.newRange)
			if len(got) != tt.want {
				t.Errorf("mergeVersionRanges(%v, %q) = %v (len %d), want len %d", tt.existing, tt.newRange, got, len(got), tt.want)
			}
		})
	}
}

func TestNormaliseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"critical", "critical"},
		{"CRITICAL", "critical"},
		{"high", "high"},
		{"HIGH", "high"},
		{"moderate", "moderate"},
		{"medium", "moderate"},
		{"MEDIUM", "moderate"},
		{"low", "low"},
		{"LOW", "low"},
		{"unknown", "critical"}, // Default to critical for malware
		{"", "critical"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normaliseSeverity(tt.input)
			if got != tt.want {
				t.Errorf("normaliseSeverity(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractNextCursor(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{"empty header", "", ""},
		{
			"single next link",
			`<https://api.github.com/advisories?after=cursor123>; rel="next"`,
			"cursor123",
		},
		{
			"next and last links",
			`<https://api.github.com/advisories?after=cursor456>; rel="next", <https://api.github.com/advisories?after=last>; rel="last"`,
			"cursor456",
		},
		{
			"only last link",
			`<https://api.github.com/advisories?after=last>; rel="last"`,
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractNextCursor(tt.header)
			if got != tt.want {
				t.Errorf("extractNextCursor(%q) = %q, want %q", tt.header, got, tt.want)
			}
		})
	}
}

func TestGitHubAdvisorySource_Fetch_Pagination(t *testing.T) {
	// This test verifies the pagination logic with a full first page

	requestCount := 0
	var serverURL string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		cursor := r.URL.Query().Get("after")

		var advisories []gitHubAdvisory
		var linkHeader string

		switch cursor {
		case "":
			// First page - must return gitHubPageSize (100) advisories to trigger pagination
			advisories = make([]gitHubAdvisory, 100)
			for i := 0; i < 100; i++ {
				advisories[i] = gitHubAdvisory{
					GHSAID:   "GHSA-page1-" + string(rune('A'+i%26)) + string(rune('0'+i/26)),
					Severity: "critical",
					Vulnerabilities: []gitHubVulnerability{
						{
							Package:                gitHubPackage{Ecosystem: "npm", Name: "pkg-page1"},
							VulnerableVersionRange: "= 1.0.0",
						},
					},
				}
			}
			linkHeader = `<` + serverURL + `?after=page2cursor>; rel="next"`
		case "page2cursor":
			// Second page (fewer than pageSize, indicates last page)
			advisories = []gitHubAdvisory{
				{
					GHSAID:   "GHSA-page2-0001",
					Severity: "high",
					Vulnerabilities: []gitHubVulnerability{
						{
							Package:                gitHubPackage{Ecosystem: "npm", Name: "pkg-page2"},
							VulnerableVersionRange: "= 2.0.0",
						},
					},
				},
			}
			// No next link, last page
		}

		w.Header().Set("Content-Type", "application/json")
		if linkHeader != "" {
			w.Header().Set("Link", linkHeader)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(advisories)
	}))
	defer server.Close()
	serverURL = server.URL

	src := NewGitHubAdvisorySource(withGitHubURL(serverURL))
	ctx := context.Background()

	data, err := src.Fetch(ctx, server.Client())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if requestCount != 2 {
		t.Errorf("Expected 2 requests for pagination, got %d", requestCount)
	}

	// Should have both packages (page1 packages are same, page2 has different one)
	if len(data.Packages) != 2 {
		t.Errorf("len(Packages) = %d, want 2 (pkg-page1, pkg-page2)", len(data.Packages))
	}

	if _, ok := data.Packages["pkg-page1"]; !ok {
		t.Error("Missing package from page 1")
	}
	if _, ok := data.Packages["pkg-page2"]; !ok {
		t.Error("Missing package from page 2")
	}
}
