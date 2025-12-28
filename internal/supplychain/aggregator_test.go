package supplychain

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/seanhalberthal/supplyscan/internal/types"
)

// mockSource implements IOCSource for testing
type mockSource struct {
	name     string
	cacheTTL time.Duration
	data     *types.SourceData
	err      error
	fetchFn  func(ctx context.Context, client *http.Client) (*types.SourceData, error)
}

func (m *mockSource) Name() string {
	return m.name
}

func (m *mockSource) CacheTTL() time.Duration {
	return m.cacheTTL
}

func (m *mockSource) Fetch(ctx context.Context, client *http.Client) (*types.SourceData, error) {
	if m.fetchFn != nil {
		return m.fetchFn(ctx, client)
	}
	return m.data, m.err
}

func TestNewAggregator(t *testing.T) {
	sources := []IOCSource{
		&mockSource{name: "source1", cacheTTL: time.Hour},
		&mockSource{name: "source2", cacheTTL: 2 * time.Hour},
	}

	agg, err := newAggregator(sources)
	if err != nil {
		t.Fatalf("NewAggregator() error = %v", err)
	}

	if agg == nil {
		t.Fatal("NewAggregator() returned nil")
	}

	if len(agg.sources) != 2 {
		t.Errorf("len(sources) = %d, want 2", len(agg.sources))
	}
}

func TestNewAggregator_WithOptions(t *testing.T) {
	sources := []IOCSource{&mockSource{name: "test"}}
	customClient := &http.Client{Timeout: 5 * time.Second}

	agg, err := newAggregator(sources, withAggregatorHTTPClient(customClient))
	if err != nil {
		t.Fatalf("NewAggregator() error = %v", err)
	}

	if agg.httpClient != customClient {
		t.Error("httpClient not set correctly")
	}
}

func TestAggregator_EnsureLoaded_Success(t *testing.T) {
	sourceData := &types.SourceData{
		Source:   "mock",
		Campaign: "test-campaign",
		Packages: map[string]types.SourcePackage{
			"test-pkg": {
				Name:     "test-pkg",
				Versions: []string{"1.0.0"},
				Severity: "critical",
			},
		},
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
	}

	sources := []IOCSource{
		&mockSource{
			name:     "mock",
			cacheTTL: time.Hour,
			data:     sourceData,
		},
	}

	agg, err := newAggregator(sources, withAggregatorCacheDir(t.TempDir()))
	if err != nil {
		t.Fatalf("NewAggregator() error = %v", err)
	}

	ctx := context.Background()
	if err := agg.ensureLoaded(ctx); err != nil {
		t.Fatalf("EnsureLoaded() error = %v", err)
	}

	db := agg.getDatabase()
	if db == nil {
		t.Fatal("GetDatabase() returned nil after EnsureLoaded")
	}

	if len(db.Packages) != 1 {
		t.Errorf("len(Packages) = %d, want 1", len(db.Packages))
	}

	if pkg, ok := db.Packages["test-pkg"]; !ok {
		t.Error("Packages missing 'test-pkg'")
	} else if len(pkg.Sources) != 1 || pkg.Sources[0] != "mock" {
		t.Errorf("pkg.Sources = %v, want [mock]", pkg.Sources)

	}
}

func TestAggregator_EnsureLoaded_MultipleSources(t *testing.T) {
	source1Data := &types.SourceData{
		Source:   "source1",
		Campaign: "campaign1",
		Packages: map[string]types.SourcePackage{
			"pkg-a":      {Name: "pkg-a", Versions: []string{"1.0.0"}, Severity: "critical"},
			"pkg-shared": {Name: "pkg-shared", Versions: []string{"1.0.0"}, Severity: "high"},
		},
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
	}

	source2Data := &types.SourceData{
		Source:   "source2",
		Campaign: "campaign2",
		Packages: map[string]types.SourcePackage{
			"pkg-b":      {Name: "pkg-b", Versions: []string{"2.0.0"}, Severity: "critical", AdvisoryID: "GHSA-1234"},
			"pkg-shared": {Name: "pkg-shared", Versions: []string{"1.0.1", "1.0.2"}, Severity: "critical", AdvisoryID: "GHSA-5678"},
		},
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
	}

	sources := []IOCSource{
		&mockSource{name: "source1", cacheTTL: time.Hour, data: source1Data},
		&mockSource{name: "source2", cacheTTL: 2 * time.Hour, data: source2Data},
	}

	agg, err := newAggregator(sources, withAggregatorCacheDir(t.TempDir()))
	if err != nil {
		t.Fatalf("NewAggregator() error = %v", err)
	}

	ctx := context.Background()
	if err := agg.ensureLoaded(ctx); err != nil {
		t.Fatalf("EnsureLoaded() error = %v", err)
	}

	db := agg.getDatabase()
	if db == nil {
		t.Fatal("GetDatabase() returned nil")
	}

	// Should have 3 packages (pkg-a, pkg-b, pkg-shared merged)
	if len(db.Packages) != 3 {
		t.Errorf("len(Packages) = %d, want 3", len(db.Packages))
	}

	// Check merged pkg-shared
	pkg, ok := db.Packages["pkg-shared"]
	if !ok {
		t.Fatal("Packages missing 'pkg-shared'")
	}
	if len(pkg.Versions) != 3 {
		t.Errorf("pkg-shared versions = %v, want 3 versions", pkg.Versions)
	}
	// Should have both sources
	if len(pkg.Sources) != 2 {
		t.Errorf("pkg-shared sources = %v, want 2 sources", pkg.Sources)
	}
	// Should have both campaigns
	if len(pkg.Campaigns) != 2 {
		t.Errorf("pkg-shared campaigns = %v, want 2 campaigns", pkg.Campaigns)
	}

	// Check db.Sources
	if len(db.Sources) != 2 {
		t.Errorf("len(db.Sources) = %d, want 2", len(db.Sources))
	}
}

func TestAggregator_EnsureLoaded_PartialFailure(t *testing.T) {
	sourceData := &types.SourceData{
		Source:   "working",
		Campaign: "test",
		Packages: map[string]types.SourcePackage{
			"pkg": {Name: "pkg", Versions: []string{"1.0.0"}},
		},
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
	}

	sources := []IOCSource{
		&mockSource{name: "working", cacheTTL: time.Hour, data: sourceData},
		&mockSource{name: "failing", cacheTTL: time.Hour, err: errors.New("fetch failed")},
	}

	agg, err := newAggregator(sources, withAggregatorCacheDir(t.TempDir()))
	if err != nil {
		t.Fatalf("NewAggregator() error = %v", err)
	}

	ctx := context.Background()
	// Should not return error - graceful degradation
	if err := agg.ensureLoaded(ctx); err != nil {
		t.Fatalf("EnsureLoaded() error = %v, expected graceful degradation", err)
	}

	db := agg.getDatabase()
	if db == nil {
		t.Fatal("GetDatabase() returned nil, expected data from working source")
	}

	if len(db.Packages) != 1 {
		t.Errorf("len(Packages) = %d, want 1 (from working source)", len(db.Packages))
	}
}

func TestAggregator_EnsureLoaded_AllFail(t *testing.T) {
	sources := []IOCSource{
		&mockSource{name: "fail1", cacheTTL: time.Hour, err: errors.New("fail1")},
		&mockSource{name: "fail2", cacheTTL: time.Hour, err: errors.New("fail2")},
	}

	agg, err := newAggregator(sources, withAggregatorCacheDir(t.TempDir()))
	if err != nil {
		t.Fatalf("NewAggregator() error = %v", err)
	}

	ctx := context.Background()
	// Should not error - soft fail with nil db
	if err := agg.ensureLoaded(ctx); err != nil {
		t.Fatalf("EnsureLoaded() error = %v, expected soft fail", err)
	}

	// Database may be nil, which is acceptable
	db := agg.getDatabase()
	if db != nil && len(db.Packages) > 0 {
		t.Error("Expected empty or nil database when all sources fail")
	}
}

func TestAggregator_Refresh_Force(t *testing.T) {
	fetchCount := 0
	sourceData := &types.SourceData{
		Source:   "mock",
		Campaign: "test",
		Packages: map[string]types.SourcePackage{
			"pkg": {Name: "pkg", Versions: []string{"1.0.0"}},
		},
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
	}

	sources := []IOCSource{
		&mockSource{
			name:     "mock",
			cacheTTL: time.Hour,
			fetchFn: func(ctx context.Context, client *http.Client) (*types.SourceData, error) {
				fetchCount++
				return sourceData, nil
			},
		},
	}

	agg, err := newAggregator(sources, withAggregatorCacheDir(t.TempDir()))
	if err != nil {
		t.Fatalf("NewAggregator() error = %v", err)
	}

	ctx := context.Background()

	// First refresh
	result1, err := agg.refresh(ctx, false)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if !result1.Updated {
		t.Error("First Refresh should have Updated = true")
	}

	// Second refresh without force - should use cache
	_, err = agg.refresh(ctx, false)
	if err != nil {
		t.Fatalf("Second Refresh() error = %v", err)
	}

	// Force refresh - should fetch again
	result3, err := agg.refresh(ctx, true)
	if err != nil {
		t.Fatalf("Force Refresh() error = %v", err)
	}
	if !result3.Updated {
		t.Error("Force Refresh should have Updated = true")
	}

	if fetchCount < 2 {
		t.Errorf("Expected at least 2 fetches (initial + force), got %d", fetchCount)
	}
}

func TestAggregator_GetStatus(t *testing.T) {
	sourceData := &types.SourceData{
		Source:   "mock",
		Campaign: "test",
		Packages: map[string]types.SourcePackage{
			"pkg1": {Name: "pkg1", Versions: []string{"1.0.0"}},
			"pkg2": {Name: "pkg2", Versions: []string{"2.0.0", "2.0.1"}},
		},
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
	}

	sources := []IOCSource{
		&mockSource{name: "mock", cacheTTL: time.Hour, data: sourceData},
	}

	agg, err := newAggregator(sources, withAggregatorCacheDir(t.TempDir()))
	if err != nil {
		t.Fatalf("NewAggregator() error = %v", err)
	}

	ctx := context.Background()
	_ = agg.ensureLoaded(ctx)

	status := agg.getStatus()

	if len(status.Sources) != 1 {
		t.Errorf("len(Sources) = %d, want 1", len(status.Sources))
	}

	if status.Packages != 2 {
		t.Errorf("Packages = %d, want 2", status.Packages)
	}

	if status.Versions != 3 {
		t.Errorf("Versions = %d, want 3", status.Versions)
	}
}

func TestUniqueStrings(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  int
	}{
		{"no duplicates", []string{"a", "b", "c"}, 3},
		{"with duplicates", []string{"a", "b", "a", "c", "b"}, 3},
		{"empty", []string{}, 0},
		{"single", []string{"a"}, 1},
		{"all same", []string{"a", "a", "a"}, 1},
		{"with empty strings", []string{"a", "", "b", ""}, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := uniqueStrings(tt.input)
			if len(got) != tt.want {
				t.Errorf("uniqueStrings(%v) = %v (len %d), want len %d", tt.input, got, len(got), tt.want)
			}
		})
	}
}

func TestAggregator_MergeSourceData(t *testing.T) {
	source1 := &types.SourceData{
		Source:   "source1",
		Campaign: "campaign1",
		Packages: map[string]types.SourcePackage{
			"pkg": {
				Name:       "pkg",
				Versions:   []string{"1.0.0"},
				AdvisoryID: "ADV-1",
				Severity:   "high",
			},
		},
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
	}

	source2 := &types.SourceData{
		Source:   "source2",
		Campaign: "campaign2",
		Packages: map[string]types.SourcePackage{
			"pkg": {
				Name:       "pkg",
				Versions:   []string{"1.0.1", "1.0.2"},
				AdvisoryID: "ADV-2",
				Severity:   "critical",
			},
		},
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
	}

	sources := []IOCSource{
		&mockSource{name: "source1", cacheTTL: time.Hour, data: source1},
		&mockSource{name: "source2", cacheTTL: time.Hour, data: source2},
	}

	agg, _ := newAggregator(sources, withAggregatorCacheDir(t.TempDir()))
	ctx := context.Background()
	_ = agg.ensureLoaded(ctx)

	db := agg.getDatabase()
	pkg := db.Packages["pkg"]

	// Check versions are merged
	if len(pkg.Versions) != 3 {
		t.Errorf("Merged pkg.Versions = %v, want 3 versions", pkg.Versions)
	}

	// Check sources are merged
	if len(pkg.Sources) != 2 {
		t.Errorf("Merged pkg.Sources = %v, want 2 sources", pkg.Sources)
	}

	// Check campaigns are merged
	if len(pkg.Campaigns) != 2 {
		t.Errorf("Merged pkg.Campaigns = %v, want 2 campaigns", pkg.Campaigns)
	}

	// Check advisory IDs are merged
	if len(pkg.AdvisoryIDs) != 2 {
		t.Errorf("Merged pkg.AdvisoryIDs = %v, want 2 advisory IDs", pkg.AdvisoryIDs)
	}
}
