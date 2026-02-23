package sources

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/seanhalberthal/supplyscan/internal/types"
)

func TestOSVSource_Name(t *testing.T) {
	src := NewOSVSource()
	if got := src.Name(); got != "osv" {
		t.Errorf("Name() = %q, want %q", got, "osv")
	}
}

func TestOSVSource_CacheTTL(t *testing.T) {
	src := NewOSVSource()
	if got := src.CacheTTL(); got != osvCacheTTL {
		t.Errorf("CacheTTL() = %v, want %v", got, osvCacheTTL)
	}
}

func TestOSVSource_WithOptions(t *testing.T) {
	customList := "https://example.com/list"
	customBase := "https://example.com/base"

	src := NewOSVSource(
		WithOSVListURL(customList),
		WithOSVBaseURL(customBase),
	)

	if src.listURL != customList {
		t.Errorf("listURL = %q, want %q", src.listURL, customList)
	}
	if src.baseURL != customBase {
		t.Errorf("baseURL = %q, want %q", src.baseURL, customBase)
	}
}

func TestOSVSource_Fetch_Success(t *testing.T) {
	// Mock GCS list response
	listResponse := gcsListResponse{
		Items: []gcsObject{
			{Name: "npm/MAL-2025-0001.json"},
			{Name: "npm/MAL-2025-0002.json"},
		},
	}

	// Mock OSV vulnerability entries
	vuln1 := osvVulnerability{
		ID:      "MAL-2025-0001",
		Summary: "Malicious package: evil-pkg",
		Aliases: []string{"GHSA-aaaa-bbbb-cccc"},
		Affected: []osvAffected{
			{
				Package:  osvPackage{Ecosystem: "npm", Name: "evil-pkg"},
				Versions: []string{"1.0.0", "1.0.1"},
			},
		},
	}

	vuln2 := osvVulnerability{
		ID:      "MAL-2025-0002",
		Summary: "Malicious package: typosquat-lodash",
		Affected: []osvAffected{
			{
				Package: osvPackage{Ecosystem: "npm", Name: "typosquat-lodash"},
				Ranges: []osvRange{
					{
						Type: "SEMVER",
						Events: []osvEvent{
							{Introduced: "0"},
						},
					},
				},
			},
		},
	}

	// Set up test server
	mux := http.NewServeMux()

	// GCS list endpoint
	mux.HandleFunc("/list", func(w http.ResponseWriter, r *http.Request) {
		// Verify prefix parameter
		if prefix := r.URL.Query().Get("prefix"); prefix != "npm/MAL-" {
			t.Errorf("expected prefix=npm/MAL-, got %q", prefix)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(listResponse)
	})

	// Individual entry endpoints
	mux.HandleFunc("/npm/MAL-2025-0001.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(vuln1)
	})
	mux.HandleFunc("/npm/MAL-2025-0002.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(vuln2)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	src := NewOSVSource(
		WithOSVListURL(server.URL+"/list"),
		WithOSVBaseURL(server.URL),
	)
	ctx := context.Background()

	data, err := src.Fetch(ctx, server.Client())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if data == nil {
		t.Fatal("Fetch() returned nil data")
	}

	if data.Source != "osv" {
		t.Errorf("Source = %q, want %q", data.Source, "osv")
	}

	if data.Campaign != osvCampaign {
		t.Errorf("Campaign = %q, want %q", data.Campaign, osvCampaign)
	}

	// Should have 2 packages
	if len(data.Packages) != 2 {
		t.Fatalf("len(Packages) = %d, want 2", len(data.Packages))
	}

	// Check evil-pkg (explicit versions)
	pkg, ok := data.Packages["evil-pkg"]
	if !ok {
		t.Fatal("Packages missing 'evil-pkg'")
	}
	if len(pkg.Versions) != 2 {
		t.Errorf("evil-pkg versions = %v, want 2 versions", pkg.Versions)
	}
	if pkg.AdvisoryID != "GHSA-aaaa-bbbb-cccc" {
		t.Errorf("evil-pkg AdvisoryID = %q, want GHSA-aaaa-bbbb-cccc (should prefer GHSA alias)", pkg.AdvisoryID)
	}
	if pkg.Severity != "critical" {
		t.Errorf("evil-pkg Severity = %q, want critical", pkg.Severity)
	}

	// Check typosquat-lodash (all versions via range)
	if pkg, ok := data.Packages["typosquat-lodash"]; !ok {
		t.Error("Packages missing 'typosquat-lodash'")
	} else {
		if len(pkg.Versions) != 1 || pkg.Versions[0] != ">= 0" {
			t.Errorf("typosquat-lodash versions = %v, want [>= 0]", pkg.Versions)
		}
		if pkg.AdvisoryID != "MAL-2025-0002" {
			t.Errorf("typosquat-lodash AdvisoryID = %q, want MAL-2025-0002 (no GHSA alias)", pkg.AdvisoryID)
		}
	}
}

func TestOSVSource_Fetch_EmptyList(t *testing.T) {
	listResponse := gcsListResponse{Items: nil}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(listResponse)
	}))
	defer server.Close()

	src := NewOSVSource(WithOSVListURL(server.URL))
	ctx := context.Background()

	data, err := src.Fetch(ctx, server.Client())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if len(data.Packages) != 0 {
		t.Errorf("len(Packages) = %d, want 0", len(data.Packages))
	}
}

func TestOSVSource_Fetch_ListError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("error"))
	}))
	defer server.Close()

	src := NewOSVSource(WithOSVListURL(server.URL))
	ctx := context.Background()

	_, err := src.Fetch(ctx, server.Client())
	if err == nil {
		t.Error("Fetch() expected error for list failure")
	}
}

func TestOSVSource_Fetch_EntryFetchError(t *testing.T) {
	// List returns entries but individual fetch fails — should gracefully skip
	listResponse := gcsListResponse{
		Items: []gcsObject{
			{Name: "npm/MAL-2025-0001.json"},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/list", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(listResponse)
	})
	mux.HandleFunc("/npm/MAL-2025-0001.json", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	src := NewOSVSource(
		WithOSVListURL(server.URL+"/list"),
		WithOSVBaseURL(server.URL),
	)
	ctx := context.Background()

	data, err := src.Fetch(ctx, server.Client())
	if err != nil {
		t.Fatalf("Fetch() error = %v (should gracefully handle entry errors)", err)
	}

	// Should return empty packages since the only entry failed
	if len(data.Packages) != 0 {
		t.Errorf("len(Packages) = %d, want 0", len(data.Packages))
	}
}

func TestOSVSource_Fetch_ContextCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	src := NewOSVSource(WithOSVListURL(server.URL))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := src.Fetch(ctx, server.Client())
	if err == nil {
		t.Error("Fetch() expected error for cancelled context")
	}
}

func TestOSVSource_Fetch_NonNpmFiltered(t *testing.T) {
	// Entry that affects Python, not npm — should be filtered out
	listResponse := gcsListResponse{
		Items: []gcsObject{
			{Name: "npm/MAL-2025-0001.json"},
		},
	}

	vuln := osvVulnerability{
		ID: "MAL-2025-0001",
		Affected: []osvAffected{
			{
				Package:  osvPackage{Ecosystem: "PyPI", Name: "python-malware"},
				Versions: []string{"1.0.0"},
			},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/list", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(listResponse)
	})
	mux.HandleFunc("/npm/MAL-2025-0001.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(vuln)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	src := NewOSVSource(
		WithOSVListURL(server.URL+"/list"),
		WithOSVBaseURL(server.URL),
	)
	ctx := context.Background()

	data, err := src.Fetch(ctx, server.Client())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if len(data.Packages) != 0 {
		t.Errorf("len(Packages) = %d, want 0 (non-npm should be filtered)", len(data.Packages))
	}
}

func TestOSVSource_Fetch_Pagination(t *testing.T) {
	requestCount := 0

	mux := http.NewServeMux()
	mux.HandleFunc("/list", func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		pageToken := r.URL.Query().Get("pageToken")

		var resp gcsListResponse
		if pageToken == "" {
			resp = gcsListResponse{
				Items:         []gcsObject{{Name: "npm/MAL-2025-0001.json"}},
				NextPageToken: "page2",
			}
		} else {
			resp = gcsListResponse{
				Items: []gcsObject{{Name: "npm/MAL-2025-0002.json"}},
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	vuln := osvVulnerability{
		ID: "MAL-2025-0001",
		Affected: []osvAffected{
			{
				Package:  osvPackage{Ecosystem: "npm", Name: "pkg1"},
				Versions: []string{"1.0.0"},
			},
		},
	}
	vuln2 := osvVulnerability{
		ID: "MAL-2025-0002",
		Affected: []osvAffected{
			{
				Package:  osvPackage{Ecosystem: "npm", Name: "pkg2"},
				Versions: []string{"2.0.0"},
			},
		},
	}

	mux.HandleFunc("/npm/MAL-2025-0001.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(vuln)
	})
	mux.HandleFunc("/npm/MAL-2025-0002.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(vuln2)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	src := NewOSVSource(
		WithOSVListURL(server.URL+"/list"),
		WithOSVBaseURL(server.URL),
	)
	ctx := context.Background()

	data, err := src.Fetch(ctx, server.Client())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if requestCount != 2 {
		t.Errorf("Expected 2 list requests for pagination, got %d", requestCount)
	}

	if len(data.Packages) != 2 {
		t.Errorf("len(Packages) = %d, want 2", len(data.Packages))
	}
}

func TestExtractOSVVersions(t *testing.T) {
	tests := []struct {
		name     string
		affected osvAffected
		want     []string
	}{
		{
			name: "explicit versions",
			affected: osvAffected{
				Versions: []string{"1.0.0", "1.0.1"},
			},
			want: []string{"1.0.0", "1.0.1"},
		},
		{
			name: "all versions via range (introduced 0, no fix)",
			affected: osvAffected{
				Ranges: []osvRange{
					{
						Type:   "SEMVER",
						Events: []osvEvent{{Introduced: "0"}},
					},
				},
			},
			want: []string{">= 0"},
		},
		{
			name: "range with fix (not all versions)",
			affected: osvAffected{
				Ranges: []osvRange{
					{
						Type: "SEMVER",
						Events: []osvEvent{
							{Introduced: "0"},
							{Fixed: "2.0.0"},
						},
					},
				},
			},
			want: nil,
		},
		{
			name:     "empty affected",
			affected: osvAffected{},
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractOSVVersions(&tt.affected)
			if len(got) != len(tt.want) {
				t.Errorf("extractOSVVersions() = %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("extractOSVVersions()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestMergeOSVVersions(t *testing.T) {
	tests := []struct {
		name     string
		existing []string
		new      []string
		wantLen  int
	}{
		{"no overlap", []string{"1.0.0"}, []string{"2.0.0"}, 2},
		{"with overlap", []string{"1.0.0"}, []string{"1.0.0", "2.0.0"}, 2},
		{"empty existing", nil, []string{"1.0.0"}, 1},
		{"empty new", []string{"1.0.0"}, nil, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeOSVVersions(tt.existing, tt.new)
			if len(got) != tt.wantLen {
				t.Errorf("mergeOSVVersions() len = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestMergeOSVVulnerability(t *testing.T) {
	packages := make(map[string]types.SourcePackage)

	// First vulnerability
	vuln1 := &osvVulnerability{
		ID:      "MAL-2025-0001",
		Aliases: []string{"GHSA-test-1234"},
		Affected: []osvAffected{
			{
				Package:  osvPackage{Ecosystem: "npm", Name: "test-pkg"},
				Versions: []string{"1.0.0"},
			},
		},
	}

	mergeOSVVulnerability(packages, vuln1)

	if len(packages) != 1 {
		t.Fatalf("Expected 1 package, got %d", len(packages))
	}
	if packages["test-pkg"].AdvisoryID != "GHSA-test-1234" {
		t.Errorf("AdvisoryID = %q, want GHSA-test-1234", packages["test-pkg"].AdvisoryID)
	}

	// Second vulnerability for same package — should merge versions
	vuln2 := &osvVulnerability{
		ID: "MAL-2025-0002",
		Affected: []osvAffected{
			{
				Package:  osvPackage{Ecosystem: "npm", Name: "test-pkg"},
				Versions: []string{"2.0.0"},
			},
		},
	}

	mergeOSVVulnerability(packages, vuln2)

	if len(packages) != 1 {
		t.Fatalf("Expected 1 package after merge, got %d", len(packages))
	}
	if len(packages["test-pkg"].Versions) != 2 {
		t.Errorf("Expected 2 versions after merge, got %v", packages["test-pkg"].Versions)
	}
}
