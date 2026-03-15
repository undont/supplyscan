package sources

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/seanhalberthal/supplyscan/internal/types"
)

// buildTestZip creates an in-memory zip archive from a map of filename -> vulnerability.
func buildTestZip(t *testing.T, entries map[string]*osvVulnerability) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	for name, vuln := range entries {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("failed to create zip entry %q: %v", name, err)
		}
		if err := json.NewEncoder(f).Encode(vuln); err != nil {
			t.Fatalf("failed to encode entry %q: %v", name, err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}

	return buf.Bytes()
}

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
	customZip := "https://example.com/all.zip"

	src := NewOSVSource(WithOSVZipURL(customZip))

	if src.zipURL != customZip {
		t.Errorf("zipURL = %q, want %q", src.zipURL, customZip)
	}
}

func TestOSVSource_Fetch_Success(t *testing.T) {
	vuln1 := &osvVulnerability{
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

	vuln2 := &osvVulnerability{
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

	zipData := buildTestZip(t, map[string]*osvVulnerability{
		"MAL-2025-0001.json": vuln1,
		"MAL-2025-0002.json": vuln2,
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipData)
	}))
	defer server.Close()

	src := NewOSVSource(WithOSVZipURL(server.URL))
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

func TestOSVSource_Fetch_EmptyZip(t *testing.T) {
	// Zip with no MAL- entries
	zipData := buildTestZip(t, map[string]*osvVulnerability{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipData)
	}))
	defer server.Close()

	src := NewOSVSource(WithOSVZipURL(server.URL))
	ctx := context.Background()

	data, err := src.Fetch(ctx, server.Client())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if len(data.Packages) != 0 {
		t.Errorf("len(Packages) = %d, want 0", len(data.Packages))
	}
}

func TestOSVSource_Fetch_DownloadError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("error"))
	}))
	defer server.Close()

	src := NewOSVSource(WithOSVZipURL(server.URL))
	ctx := context.Background()

	_, err := src.Fetch(ctx, server.Client())
	if err == nil {
		t.Error("Fetch() expected error for download failure")
	}
}

func TestOSVSource_Fetch_InvalidZip(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write([]byte("not a zip file"))
	}))
	defer server.Close()

	src := NewOSVSource(WithOSVZipURL(server.URL))
	ctx := context.Background()

	_, err := src.Fetch(ctx, server.Client())
	if err == nil {
		t.Error("Fetch() expected error for invalid zip")
	}
}

func TestOSVSource_Fetch_ContextCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	src := NewOSVSource(WithOSVZipURL(server.URL))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := src.Fetch(ctx, server.Client())
	if err == nil {
		t.Error("Fetch() expected error for cancelled context")
	}
}

func TestOSVSource_Fetch_NonNpmFiltered(t *testing.T) {
	// Entry that affects Python, not npm — should be filtered out
	vuln := &osvVulnerability{
		ID: "MAL-2025-0001",
		Affected: []osvAffected{
			{
				Package:  osvPackage{Ecosystem: "PyPI", Name: "python-malware"},
				Versions: []string{"1.0.0"},
			},
		},
	}

	zipData := buildTestZip(t, map[string]*osvVulnerability{
		"MAL-2025-0001.json": vuln,
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipData)
	}))
	defer server.Close()

	src := NewOSVSource(WithOSVZipURL(server.URL))
	ctx := context.Background()

	data, err := src.Fetch(ctx, server.Client())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if len(data.Packages) != 0 {
		t.Errorf("len(Packages) = %d, want 0 (non-npm should be filtered)", len(data.Packages))
	}
}

func TestOSVSource_Fetch_NonMalwareFiltered(t *testing.T) {
	// Non-MAL entries in the zip should be skipped
	vuln := &osvVulnerability{
		ID: "GHSA-xxxx-yyyy-zzzz",
		Affected: []osvAffected{
			{
				Package:  osvPackage{Ecosystem: "npm", Name: "some-pkg"},
				Versions: []string{"1.0.0"},
			},
		},
	}

	zipData := buildTestZip(t, map[string]*osvVulnerability{
		"GHSA-xxxx-yyyy-zzzz.json": vuln,
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipData)
	}))
	defer server.Close()

	src := NewOSVSource(WithOSVZipURL(server.URL))
	ctx := context.Background()

	data, err := src.Fetch(ctx, server.Client())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if len(data.Packages) != 0 {
		t.Errorf("len(Packages) = %d, want 0 (non-MAL entries should be filtered)", len(data.Packages))
	}
}

func TestOSVSource_Fetch_MixedEntries(t *testing.T) {
	// Mix of MAL and non-MAL entries — only MAL should be processed
	malVuln := &osvVulnerability{
		ID: "MAL-2025-0001",
		Affected: []osvAffected{
			{
				Package:  osvPackage{Ecosystem: "npm", Name: "evil-pkg"},
				Versions: []string{"1.0.0"},
			},
		},
	}
	ghsaVuln := &osvVulnerability{
		ID: "GHSA-xxxx-yyyy-zzzz",
		Affected: []osvAffected{
			{
				Package:  osvPackage{Ecosystem: "npm", Name: "vulnerable-pkg"},
				Versions: []string{"2.0.0"},
			},
		},
	}

	zipData := buildTestZip(t, map[string]*osvVulnerability{
		"MAL-2025-0001.json":       malVuln,
		"GHSA-xxxx-yyyy-zzzz.json": ghsaVuln,
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipData)
	}))
	defer server.Close()

	src := NewOSVSource(WithOSVZipURL(server.URL))
	ctx := context.Background()

	data, err := src.Fetch(ctx, server.Client())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if len(data.Packages) != 1 {
		t.Fatalf("len(Packages) = %d, want 1 (only MAL entry)", len(data.Packages))
	}

	if _, ok := data.Packages["evil-pkg"]; !ok {
		t.Error("Packages missing 'evil-pkg'")
	}
	if _, ok := data.Packages["vulnerable-pkg"]; ok {
		t.Error("Packages should not contain 'vulnerable-pkg' (non-MAL entry)")
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

func TestProcessZip(t *testing.T) {
	vuln := &osvVulnerability{
		ID: "MAL-2025-0001",
		Affected: []osvAffected{
			{
				Package:  osvPackage{Ecosystem: "npm", Name: "test-pkg"},
				Versions: []string{"1.0.0"},
			},
		},
	}

	zipData := buildTestZip(t, map[string]*osvVulnerability{
		"MAL-2025-0001.json": vuln,
	})

	packages, err := processZip(zipData)
	if err != nil {
		t.Fatalf("processZip() error = %v", err)
	}

	if len(packages) != 1 {
		t.Fatalf("len(packages) = %d, want 1", len(packages))
	}

	if _, ok := packages["test-pkg"]; !ok {
		t.Error("packages missing 'test-pkg'")
	}
}

func TestProcessZip_InvalidData(t *testing.T) {
	_, err := processZip([]byte("not a zip"))
	if err == nil {
		t.Error("processZip() expected error for invalid zip data")
	}
}
