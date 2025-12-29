package supplychain

import (
	"context"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/seanhalberthal/supplyscan/internal/types"
)

// aggregator manages multiple IOC sources and merges their data.
type aggregator struct {
	sources    []IOCSource
	cache      *multiSourceCache
	httpClient *http.Client
	mu         sync.RWMutex
	db         *types.IOCDatabase
}

// AggregatorOption configures an aggregator.
type AggregatorOption func(*aggregator)

// withAggregatorHTTPClient sets a custom HTTP client.
func withAggregatorHTTPClient(client *http.Client) AggregatorOption {
	return func(a *aggregator) {
		a.httpClient = client
	}
}

// withAggregatorCacheDir sets a custom cache directory.
func withAggregatorCacheDir(dir string) AggregatorOption {
	return func(a *aggregator) {
		// Always create new cache with custom dir
		cache, err := newMultiSourceCache(dir)
		if err == nil {
			a.cache = cache
		}
	}
}

// newAggregator creates a new IOC aggregator with the given sources.
func newAggregator(sources []IOCSource, opts ...AggregatorOption) (*aggregator, error) {
	cache, err := newMultiSourceCache("")
	if err != nil {
		return nil, err
	}

	agg := &aggregator{
		sources:    sources,
		cache:      cache,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}

	for _, opt := range opts {
		opt(agg)
	}

	return agg, nil
}

// ensureLoaded loads the IOC database, fetching from sources if needed.
func (a *aggregator) ensureLoaded(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// If already loaded and all sources are fresh, return
	if a.db != nil && a.allSourcesFresh() {
		return nil
	}

	// Try to load from merged cache first
	db, err := a.cache.loadMerged()
	if err == nil && db != nil && a.allSourcesFresh() {
		a.db = db
		return nil
	}

	// Fetch from sources
	sourceData, _ := a.fetchAll(ctx, false)

	// If we got no data but have cached data, use it (graceful degradation)
	if len(sourceData) == 0 {
		if db != nil {
			a.db = db
		}
		return nil
	}

	// Merge source data into unified database
	a.db = a.mergeSourceData(sourceData)

	// Save to cache (best effort)
	sourceStatuses := a.buildSourceStatuses(sourceData)
	_ = a.cache.saveMerged(a.db, sourceStatuses)

	return nil
}

// allSourcesFresh checks if all sources have fresh cache.
func (a *aggregator) allSourcesFresh() bool {
	for _, src := range a.sources {
		if a.cache.IsSourceStale(src.Name(), src.CacheTTL()) {
			return false
		}
	}
	return true
}

// buildSourceStatuses creates a map of source statuses from source data.
func (a *aggregator) buildSourceStatuses(sourceData []*types.SourceData) map[string]*sourceStatus {
	statuses := make(map[string]*sourceStatus)
	for _, data := range sourceData {
		statuses[data.Source] = &sourceStatus{
			Name:         data.Source,
			LastFetched:  data.FetchedAt,
			Success:      true,
			PackageCount: len(data.Packages),
		}
	}
	return statuses
}

// refresh fetches fresh data from all sources.
func (a *aggregator) refresh(ctx context.Context, force bool) (*types.RefreshResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	sourceData, sourceErrors := a.fetchAll(ctx, force)

	result := &types.RefreshResult{
		SourceResults: make(map[string]types.SourceRefreshInfo),
	}

	// Track which sources were updated
	anyUpdated := false
	for _, data := range sourceData {
		anyUpdated = true
		result.SourceResults[data.Source] = types.SourceRefreshInfo{
			Name:         data.Source,
			Updated:      true,
			PackageCount: len(data.Packages),
		}
	}

	// Track errors
	for name, err := range sourceErrors {
		result.SourceResults[name] = types.SourceRefreshInfo{
			Name:    name,
			Updated: false,
			Error:   err.Error(),
		}
	}

	// If no sources returned data, return early with cached data info
	if len(sourceData) == 0 {
		meta, _ := a.cache.loadMergedMeta()
		if meta != nil {
			result.PackagesCount = meta.PackageCount
			result.VersionsCount = meta.VersionCount
		}
		return result, nil
	}

	// Merge and save
	a.db = a.mergeSourceData(sourceData)

	// Count packages and versions
	result.PackagesCount = len(a.db.Packages)
	for name := range a.db.Packages {
		result.VersionsCount += len(a.db.Packages[name].Versions)
	}
	result.Updated = anyUpdated
	result.CacheAgeHours = 0

	// Save to cache
	sourceStatuses := make(map[string]*sourceStatus)
	for _, data := range sourceData {
		sourceStatuses[data.Source] = &sourceStatus{
			Name:         data.Source,
			LastFetched:  data.FetchedAt,
			Success:      true,
			PackageCount: len(data.Packages),
		}
	}
	_ = a.cache.saveMerged(a.db, sourceStatuses)

	return result, nil
}

// getDatabase returns the current IOC database.
func (a *aggregator) getDatabase() *types.IOCDatabase {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.db
}

// getStatus returns the status of all IOC sources.
func (a *aggregator) getStatus() types.IOCDatabaseStatus {
	a.mu.RLock()
	defer a.mu.RUnlock()

	status := types.IOCDatabaseStatus{
		Sources:       make([]string, 0, len(a.sources)),
		SourceDetails: make(map[string]types.SourceStatusInfo),
	}

	for _, src := range a.sources {
		status.Sources = append(status.Sources, src.Name())

		meta, err := a.cache.loadSourceMeta(src.Name())
		if err == nil && meta != nil {
			status.SourceDetails[src.Name()] = types.SourceStatusInfo{
				LastFetched:  meta.LastFetched,
				Success:      meta.Success,
				Error:        meta.Error,
				PackageCount: meta.PackageCount,
			}
		}
	}

	if a.db != nil {
		status.Packages = len(a.db.Packages)
		for name := range a.db.Packages {
			status.Versions += len(a.db.Packages[name].Versions)
		}
		status.LastUpdated = a.db.LastUpdated
	}

	return status
}

// fetchAll fetches data from all sources in parallel.
func (a *aggregator) fetchAll(ctx context.Context, force bool) ([]*types.SourceData, map[string]error) {
	var mu sync.Mutex
	results := make([]*types.SourceData, 0, len(a.sources))
	errors := make(map[string]error)

	g, ctx := errgroup.WithContext(ctx)

	for _, src := range a.sources {
		routineSrc := src // capture for goroutine

		g.Go(func() error {
			// Check if cache is fresh (unless force refresh)
			if !force && !a.cache.IsSourceStale(routineSrc.Name(), routineSrc.CacheTTL()) {
				data, err := a.cache.loadSource(routineSrc.Name())
				if err == nil && data != nil {
					mu.Lock()
					results = append(results, data)
					mu.Unlock()
					return nil
				}
			}

			// Fetch from source
			data, err := routineSrc.Fetch(ctx, a.httpClient)
			mu.Lock()
			if err != nil {
				errors[routineSrc.Name()] = err
			} else if data != nil {
				results = append(results, data)
				// Save to per-source cache (best effort)
				_ = a.cache.saveSource(routineSrc.Name(), data)
			}
			mu.Unlock()
			return nil // Don't fail the group on individual source errors
		})
	}

	_ = g.Wait() // Errors tracked per-source
	return results, errors
}

// mergeSourceData combines data from multiple sources into a single IOCDatabase.
func (a *aggregator) mergeSourceData(sources []*types.SourceData) *types.IOCDatabase {
	packages := make(map[string]types.CompromisedPackage)
	sourceSet := make(map[string]bool)

	for _, src := range sources {
		sourceSet[src.Source] = true
		a.mergeSourceIntoPackages(packages, src)
	}

	sourceList := make([]string, 0, len(sourceSet))
	for s := range sourceSet {
		sourceList = append(sourceList, s)
	}

	return &types.IOCDatabase{
		Packages:    packages,
		LastUpdated: time.Now().UTC().Format(time.RFC3339),
		Sources:     sourceList,
	}
}

// mergeSourceIntoPackages merges a single source's packages into the packages map.
func (a *aggregator) mergeSourceIntoPackages(packages map[string]types.CompromisedPackage, src *types.SourceData) {
	for name, pkg := range src.Packages {
		if existing, ok := packages[name]; ok {
			a.mergeExistingPackage(&existing, src, pkg)
			packages[name] = existing
		} else {
			packages[name] = a.createNewPackage(name, src, pkg)
		}
	}
}

// mergeExistingPackage merges a package from a new source with an existing package.
func (a *aggregator) mergeExistingPackage(existing *types.CompromisedPackage, src *types.SourceData, pkg types.SourcePackage) {
	existing.Versions = uniqueStrings(append(existing.Versions, pkg.Versions...))
	existing.Sources = uniqueStrings(append(existing.Sources, src.Source))
	if src.Campaign != "" {
		existing.Campaigns = uniqueStrings(append(existing.Campaigns, src.Campaign))
	}
	if pkg.AdvisoryID != "" {
		existing.AdvisoryIDs = uniqueStrings(append(existing.AdvisoryIDs, pkg.AdvisoryID))
	}
	// Keep earliest first seen
	if existing.FirstSeen == "" {
		existing.FirstSeen = time.Now().UTC().Format(time.RFC3339)
	}
}

// createNewPackage creates a new compromised package from source data.
func (a *aggregator) createNewPackage(name string, src *types.SourceData, pkg types.SourcePackage) types.CompromisedPackage {
	var campaigns []string
	if src.Campaign != "" {
		campaigns = []string{src.Campaign}
	}
	var advisoryIDs []string
	if pkg.AdvisoryID != "" {
		advisoryIDs = []string{pkg.AdvisoryID}
	}
	return types.CompromisedPackage{
		Name:        name,
		Versions:    pkg.Versions,
		Sources:     []string{src.Source},
		Campaigns:   campaigns,
		AdvisoryIDs: advisoryIDs,
		FirstSeen:   time.Now().UTC().Format(time.RFC3339),
	}
}

// uniqueStrings returns a deduplicated slice of strings.
func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(input))
	for _, s := range input {
		if s != "" && !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
