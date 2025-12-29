package supplychain

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/seanhalberthal/supplyscan/internal/types"
)

// multiSourceCache manages per-source IOC caching and merged database storage.
type multiSourceCache struct {
	cacheDir string
}

// newMultiSourceCache creates a new multi-source cache manager.
func newMultiSourceCache(cacheDir string) (*multiSourceCache, error) {
	if cacheDir == "" {
		dir, err := getDefaultCacheDir()
		if err != nil {
			return nil, err
		}
		cacheDir = dir
	}

	if err := os.MkdirAll(cacheDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	return &multiSourceCache{cacheDir: cacheDir}, nil
}

// getDefaultCacheDir returns the default cache directory path.
func getDefaultCacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cache", "supplyscan"), nil
}

// sourceCacheFile returns the path to a source-specific cache file.
func (c *multiSourceCache) sourceCacheFile(sourceName string) string {
	return filepath.Join(c.cacheDir, fmt.Sprintf("source_%s.json", sourceName))
}

// sourceMetaFile returns the path to a source-specific metadata file.
func (c *multiSourceCache) sourceMetaFile(sourceName string) string {
	return filepath.Join(c.cacheDir, fmt.Sprintf("source_%s_meta.json", sourceName))
}

// mergedCacheFile returns the path to the merged IOC database file.
func (c *multiSourceCache) mergedCacheFile() string {
	return filepath.Join(c.cacheDir, "iocs.json")
}

// mergedMetaFile returns the path to the merged metadata file.
func (c *multiSourceCache) mergedMetaFile() string {
	return filepath.Join(c.cacheDir, "meta.json")
}

// loadSource loads cached data for a specific source.
func (c *multiSourceCache) loadSource(sourceName string) (*types.SourceData, error) {
	path := c.sourceCacheFile(sourceName)
	// #nosec G304 -- path is derived from sourceName which is an internal identifier
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No cache exists
		}
		return nil, err
	}

	var sourceData types.SourceData
	if err := json.Unmarshal(data, &sourceData); err != nil {
		return nil, err
	}

	return &sourceData, nil
}

// saveSource saves data for a specific source to cache.
func (c *multiSourceCache) saveSource(sourceName string, data *types.SourceData) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	path := c.sourceCacheFile(sourceName)
	if err := os.WriteFile(path, jsonData, 0600); err != nil {
		return err
	}

	// Also save metadata
	meta := &sourceStatus{
		Name:         sourceName,
		LastFetched:  data.FetchedAt,
		Success:      true,
		PackageCount: len(data.Packages),
	}
	return c.saveSourceMeta(sourceName, meta)
}

// saveSourceMeta saves metadata for a specific source.
func (c *multiSourceCache) saveSourceMeta(sourceName string, meta *sourceStatus) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}

	path := c.sourceMetaFile(sourceName)
	return os.WriteFile(path, data, 0600)
}

// loadSourceMeta loads metadata for a specific source.
func (c *multiSourceCache) loadSourceMeta(sourceName string) (*sourceStatus, error) {
	path := c.sourceMetaFile(sourceName)
	// #nosec G304 -- path is derived from sourceName which is an internal identifier
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var meta sourceStatus
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}

	return &meta, nil
}

// IsSourceStale checks if a source's cache is older than the given TTL.
func (c *multiSourceCache) IsSourceStale(sourceName string, ttl time.Duration) bool {
	meta, err := c.loadSourceMeta(sourceName)
	if err != nil || meta == nil {
		return true
	}

	lastFetched, err := time.Parse(time.RFC3339, meta.LastFetched)
	if err != nil {
		return true
	}

	return time.Since(lastFetched) > ttl
}

// loadMerged loads the merged IOC database from cache.
func (c *multiSourceCache) loadMerged() (*types.IOCDatabase, error) {
	path := c.mergedCacheFile()
	// #nosec G304 -- path is constant and internal to the cache
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var db types.IOCDatabase
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, err
	}

	return &db, nil
}

// saveMerged saves the merged IOC database to cache.
func (c *multiSourceCache) saveMerged(db *types.IOCDatabase, sourceStatuses map[string]*sourceStatus) error {
	// Save the database
	jsonData, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}

	path := c.mergedCacheFile()
	if err := os.WriteFile(path, jsonData, 0600); err != nil {
		return err
	}

	// Calculate totals
	packageCount := len(db.Packages)
	versionCount := 0
	for name := range db.Packages {
		versionCount += len(db.Packages[name].Versions)
	}

	// Save metadata
	meta := &types.IOCMeta{
		LastUpdated:    db.LastUpdated,
		PackageCount:   packageCount,
		VersionCount:   versionCount,
		SourceStatuses: make(map[string]types.SourceStatusInfo),
	}

	for name, status := range sourceStatuses {
		meta.SourceStatuses[name] = types.SourceStatusInfo{
			LastFetched:  status.LastFetched,
			Success:      status.Success,
			Error:        status.Error,
			PackageCount: status.PackageCount,
		}
	}

	return c.saveMergedMeta(meta)
}

// saveMergedMeta saves the merged cache metadata.
func (c *multiSourceCache) saveMergedMeta(meta *types.IOCMeta) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}

	path := c.mergedMetaFile()
	return os.WriteFile(path, data, 0600)
}

// loadMergedMeta loads the merged cache metadata.
func (c *multiSourceCache) loadMergedMeta() (*types.IOCMeta, error) {
	path := c.mergedMetaFile()
	// #nosec G304 -- path is constant and internal to the cache
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var meta types.IOCMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}

	return &meta, nil
}
