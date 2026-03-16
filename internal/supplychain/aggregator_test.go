package supplychain

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
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

	// Verify timing is populated
	if result3.Timing == nil {
		t.Fatal("Timing is nil on refresh result")
	}
	if result3.Timing.TotalMs < 0 {
		t.Error("Timing.TotalMs should be >= 0")
	}
	if _, ok := result3.Timing.Sources["mock"]; !ok {
		t.Error("Timing.Sources missing 'mock' source timing")
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

// waitForRefreshComplete polls until the aggregator's background refresh finishes.
func waitForRefreshComplete(t *testing.T, agg *aggregator, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for background refresh to complete")
			return
		default:
			if !agg.refreshing.Load() {
				return
			}
			time.Sleep(time.Millisecond)
		}
	}
}

func TestAggregator_StaleWhileRevalidate(t *testing.T) {
	var fetchCount atomic.Int32

	sources := []IOCSource{
		&mockSource{
			name:     "test",
			cacheTTL: 10 * time.Millisecond,
			fetchFn: func(ctx context.Context, client *http.Client) (*types.SourceData, error) {
				fetchCount.Add(1)
				return &types.SourceData{
					Source:   "test",
					Campaign: "test-campaign",
					Packages: map[string]types.SourcePackage{
						"pkg": {Name: "pkg", Versions: []string{"1.0.0"}},
					},
					FetchedAt: time.Now().UTC().Format(time.RFC3339),
				}, nil
			},
		},
	}

	agg, err := newAggregator(sources, withAggregatorCacheDir(t.TempDir()))
	if err != nil {
		t.Fatalf("newAggregator() error = %v", err)
	}

	ctx := context.Background()

	// Cold start — must block and fetch
	if err := agg.ensureLoaded(ctx); err != nil {
		t.Fatalf("ensureLoaded() cold start error = %v", err)
	}
	if fetchCount.Load() != 1 {
		t.Fatalf("expected 1 fetch after cold start, got %d", fetchCount.Load())
	}

	// Wait for TTL to expire
	time.Sleep(20 * time.Millisecond)

	// Stale path — should return instantly (< 5ms), not block for fetch
	start := time.Now()
	if err := agg.ensureLoaded(ctx); err != nil {
		t.Fatalf("ensureLoaded() stale path error = %v", err)
	}
	elapsed := time.Since(start)
	if elapsed > 5*time.Millisecond {
		t.Errorf("stale-while-revalidate took %v, expected < 5ms", elapsed)
	}

	// Data should still be available (stale)
	db := agg.getDatabase()
	if db == nil {
		t.Fatal("getDatabase() returned nil during stale-while-revalidate")
	}
	if len(db.Packages) != 1 {
		t.Errorf("expected 1 package, got %d", len(db.Packages))
	}

	// Wait for background refresh to complete
	waitForRefreshComplete(t, agg, 5*time.Second)

	if fetchCount.Load() != 2 {
		t.Errorf("expected 2 total fetches (cold start + background), got %d", fetchCount.Load())
	}
}

func TestAggregator_ColdStartBlocks(t *testing.T) {
	sources := []IOCSource{
		&mockSource{
			name:     "slow",
			cacheTTL: time.Hour,
			fetchFn: func(ctx context.Context, client *http.Client) (*types.SourceData, error) {
				time.Sleep(100 * time.Millisecond)
				return &types.SourceData{
					Source:   "slow",
					Campaign: "test",
					Packages: map[string]types.SourcePackage{
						"pkg": {Name: "pkg", Versions: []string{"1.0.0"}},
					},
					FetchedAt: time.Now().UTC().Format(time.RFC3339),
				}, nil
			},
		},
	}

	agg, err := newAggregator(sources, withAggregatorCacheDir(t.TempDir()))
	if err != nil {
		t.Fatalf("newAggregator() error = %v", err)
	}

	ctx := context.Background()

	start := time.Now()
	if err := agg.ensureLoaded(ctx); err != nil {
		t.Fatalf("ensureLoaded() error = %v", err)
	}
	elapsed := time.Since(start)

	if elapsed < 100*time.Millisecond {
		t.Errorf("cold start took %v, expected >= 100ms (should block for fetch)", elapsed)
	}

	db := agg.getDatabase()
	if db == nil {
		t.Fatal("getDatabase() returned nil after cold start")
	}
	if len(db.Packages) != 1 {
		t.Errorf("expected 1 package, got %d", len(db.Packages))
	}
}

func TestAggregator_DeduplicatesBackgroundRefresh(t *testing.T) {
	var fetchCount atomic.Int32

	sources := []IOCSource{
		&mockSource{
			name:     "test",
			cacheTTL: 10 * time.Millisecond,
			fetchFn: func(ctx context.Context, client *http.Client) (*types.SourceData, error) {
				fetchCount.Add(1)
				// Simulate slow fetch so concurrent calls overlap
				time.Sleep(50 * time.Millisecond)
				return &types.SourceData{
					Source:   "test",
					Campaign: "test",
					Packages: map[string]types.SourcePackage{
						"pkg": {Name: "pkg", Versions: []string{"1.0.0"}},
					},
					FetchedAt: time.Now().UTC().Format(time.RFC3339),
				}, nil
			},
		},
	}

	agg, err := newAggregator(sources, withAggregatorCacheDir(t.TempDir()))
	if err != nil {
		t.Fatalf("newAggregator() error = %v", err)
	}

	ctx := context.Background()

	// Cold start — 1 fetch
	if err := agg.ensureLoaded(ctx); err != nil {
		t.Fatalf("ensureLoaded() cold start error = %v", err)
	}

	// Wait for TTL to expire
	time.Sleep(20 * time.Millisecond)

	// Fire 10 concurrent ensureLoaded calls — should only trigger 1 background refresh
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = agg.ensureLoaded(ctx)
		}()
	}
	wg.Wait()

	// Wait for the single background refresh to complete
	waitForRefreshComplete(t, agg, 5*time.Second)

	got := fetchCount.Load()
	if got != 2 {
		t.Errorf("expected 2 fetches (1 cold start + 1 background), got %d", got)
	}
}

func TestAggregator_ConcurrentColdStart(t *testing.T) {
	var fetchCount atomic.Int32

	sources := []IOCSource{
		&mockSource{
			name:     "test",
			cacheTTL: time.Hour,
			fetchFn: func(ctx context.Context, client *http.Client) (*types.SourceData, error) {
				fetchCount.Add(1)
				time.Sleep(100 * time.Millisecond)
				return &types.SourceData{
					Source:   "test",
					Campaign: "test",
					Packages: map[string]types.SourcePackage{
						"pkg": {Name: "pkg", Versions: []string{"1.0.0"}},
					},
					FetchedAt: time.Now().UTC().Format(time.RFC3339),
				}, nil
			},
		},
	}

	agg, err := newAggregator(sources, withAggregatorCacheDir(t.TempDir()))
	if err != nil {
		t.Fatalf("newAggregator() error = %v", err)
	}

	ctx := context.Background()

	// Fire 5 concurrent cold-start calls — only 1 should actually fetch
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = agg.ensureLoaded(ctx)
		}()
	}
	wg.Wait()

	got := fetchCount.Load()
	if got != 1 {
		t.Errorf("expected 1 fetch (deduplicated cold start), got %d", got)
	}

	db := agg.getDatabase()
	if db == nil {
		t.Fatal("getDatabase() returned nil after concurrent cold start")
	}
}

func TestAggregator_DiskCacheOnColdStart(t *testing.T) {
	cacheDir := t.TempDir()

	sourceData := &types.SourceData{
		Source:   "test",
		Campaign: "test",
		Packages: map[string]types.SourcePackage{
			"cached-pkg": {Name: "cached-pkg", Versions: []string{"1.0.0"}},
		},
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
	}

	// First aggregator: load data and write to disk cache
	agg1, err := newAggregator(
		[]IOCSource{&mockSource{name: "test", cacheTTL: time.Hour, data: sourceData}},
		withAggregatorCacheDir(cacheDir),
	)
	if err != nil {
		t.Fatalf("newAggregator() error = %v", err)
	}
	if err := agg1.ensureLoaded(context.Background()); err != nil {
		t.Fatalf("ensureLoaded() error = %v", err)
	}

	// Second aggregator: same cache dir, but source always fails
	agg2, err := newAggregator(
		[]IOCSource{&mockSource{
			name:     "test",
			cacheTTL: time.Hour,
			err:      errors.New("source unavailable"),
		}},
		withAggregatorCacheDir(cacheDir),
	)
	if err != nil {
		t.Fatalf("newAggregator() error = %v", err)
	}

	// Should load from disk cache despite failing source
	if err := agg2.ensureLoaded(context.Background()); err != nil {
		t.Fatalf("ensureLoaded() error = %v", err)
	}

	db := agg2.getDatabase()
	if db == nil {
		t.Fatal("getDatabase() returned nil — expected disk cache to be loaded")
	}
	if _, ok := db.Packages["cached-pkg"]; !ok {
		t.Error("expected 'cached-pkg' from disk cache, not found")
	}
}

func TestAggregator_StaleDataSurvivesFailedRefresh(t *testing.T) {
	var shouldFail atomic.Bool

	sources := []IOCSource{
		&mockSource{
			name:     "test",
			cacheTTL: 10 * time.Millisecond,
			fetchFn: func(ctx context.Context, client *http.Client) (*types.SourceData, error) {
				if shouldFail.Load() {
					return nil, errors.New("source unavailable")
				}
				return &types.SourceData{
					Source:   "test",
					Campaign: "test",
					Packages: map[string]types.SourcePackage{
						"original-pkg": {Name: "original-pkg", Versions: []string{"1.0.0"}},
					},
					FetchedAt: time.Now().UTC().Format(time.RFC3339),
				}, nil
			},
		},
	}

	agg, err := newAggregator(sources, withAggregatorCacheDir(t.TempDir()))
	if err != nil {
		t.Fatalf("newAggregator() error = %v", err)
	}

	ctx := context.Background()

	// Load initial data successfully
	if err := agg.ensureLoaded(ctx); err != nil {
		t.Fatalf("ensureLoaded() error = %v", err)
	}

	// Make source fail from now on
	shouldFail.Store(true)

	// Wait for TTL to expire
	time.Sleep(20 * time.Millisecond)

	// Stale path: should return immediately with stale data
	if err := agg.ensureLoaded(ctx); err != nil {
		t.Fatalf("ensureLoaded() stale path error = %v", err)
	}

	// Wait for the failed background refresh to complete
	waitForRefreshComplete(t, agg, 5*time.Second)

	// Stale data should still be intact
	db := agg.getDatabase()
	if db == nil {
		t.Fatal("getDatabase() returned nil — stale data should survive failed refresh")
	}
	if _, ok := db.Packages["original-pkg"]; !ok {
		t.Error("expected 'original-pkg' to survive failed background refresh")
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
