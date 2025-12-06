// Package supplychain provides IOC fetching and supply chain detection.
package supplychain

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/seanhalberthal/supplyscan-mcp/internal/types"
)

// DefaultIOCSourceURL is DataDog's consolidated IOC list URL.
const DefaultIOCSourceURL = "https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/shai-hulud-2.0/consolidated_iocs.csv"

// defaultCacheTTL is the cache TTL in hours.
const defaultCacheTTL = 6

// IOCCache manages the local IOC database cache.
type IOCCache struct {
	cacheDir   string
	sourceURL  string
	httpClient *http.Client
}

// CacheOption configures an IOCCache.
type CacheOption func(*IOCCache)

// WithCacheDir sets a custom cache directory.
func WithCacheDir(dir string) CacheOption {
	return func(c *IOCCache) {
		c.cacheDir = dir
	}
}

// WithSourceURL sets a custom IOC source URL.
func WithSourceURL(url string) CacheOption {
	return func(c *IOCCache) {
		c.sourceURL = url
	}
}

// WithCacheHTTPClient sets a custom HTTP client for fetching IOCs.
func WithCacheHTTPClient(client *http.Client) CacheOption {
	return func(c *IOCCache) {
		c.httpClient = client
	}
}

// newIOCCache creates a new IOC cache manager.
func newIOCCache(opts ...CacheOption) (*IOCCache, error) {
	cache := &IOCCache{
		sourceURL:  DefaultIOCSourceURL,
		httpClient: &http.Client{},
	}

	// Apply options first to allow custom cache dir
	for _, opt := range opts {
		opt(cache)
	}

	// If no custom cache dir, use default
	if cache.cacheDir == "" {
		cacheDir, err := getCacheDir()
		if err != nil {
			return nil, err
		}
		cache.cacheDir = cacheDir
	}

	if err := os.MkdirAll(cache.cacheDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	return cache, nil
}

// getCacheDir returns the cache directory path.
func getCacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cache", "supplyscan-mcp"), nil
}

// Load loads the IOC database from cache.
func (c *IOCCache) Load() (*types.IOCDatabase, error) {
	path := filepath.Join(c.cacheDir, "iocs.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No cache exists
		}
		return nil, err
	}

	var db types.IOCDatabase
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, err
	}

	return &db, nil
}

// save saves the IOC database to cache.
func (c *IOCCache) save(db *types.IOCDatabase) error {
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}

	path := filepath.Join(c.cacheDir, "iocs.json")
	return os.WriteFile(path, data, 0600)
}

// loadMeta loads the cache metadata.
func (c *IOCCache) loadMeta() (*types.IOCMeta, error) {
	path := filepath.Join(c.cacheDir, "meta.json")
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

// saveMeta saves the cache metadata.
func (c *IOCCache) saveMeta(meta *types.IOCMeta) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}

	path := filepath.Join(c.cacheDir, "meta.json")
	return os.WriteFile(path, data, 0600)
}

// isStale checks if the cache is older than the TTL.
func (c *IOCCache) isStale() bool {
	meta, err := c.loadMeta()
	if err != nil || meta == nil {
		return true
	}

	lastUpdated, err := time.Parse(time.RFC3339, meta.LastUpdated)
	if err != nil {
		return true
	}

	return time.Since(lastUpdated) > time.Duration(defaultCacheTTL)*time.Hour
}

// cacheAgeHours returns the age of the cache in hours.
func (c *IOCCache) cacheAgeHours() int {
	meta, err := c.loadMeta()
	if err != nil || meta == nil {
		return -1
	}

	lastUpdated, err := time.Parse(time.RFC3339, meta.LastUpdated)
	if err != nil {
		return -1
	}

	return int(time.Since(lastUpdated).Hours())
}

// refresh fetches the latest IOC data and updates the cache.
func (c *IOCCache) refresh(force bool) (*types.RefreshResult, error) {
	if !force && !c.isStale() {
		// Cache is still fresh
		meta, _ := c.loadMeta()
		return &types.RefreshResult{
			Updated:       false,
			PackagesCount: meta.PackageCount,
			VersionsCount: meta.VersionCount,
			CacheAgeHours: c.cacheAgeHours(),
		}, nil
	}

	// Fetch from upstream
	db, err := c.fetchIOCs()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch IOCs: %w", err)
	}

	// Count packages and versions
	packageCount := len(db.Packages)
	versionCount := 0
	for _, pkg := range db.Packages {
		versionCount += len(pkg.Versions)
	}

	// Save to cache
	if err := c.save(db); err != nil {
		return nil, fmt.Errorf("failed to save IOC cache: %w", err)
	}

	// Update metadata
	meta := &types.IOCMeta{
		LastUpdated:  time.Now().UTC().Format(time.RFC3339),
		PackageCount: packageCount,
		VersionCount: versionCount,
	}
	if err := c.saveMeta(meta); err != nil {
		return nil, fmt.Errorf("failed to save cache metadata: %w", err)
	}

	return &types.RefreshResult{
		Updated:       true,
		PackagesCount: packageCount,
		VersionsCount: versionCount,
		CacheAgeHours: 0,
	}, nil
}

// fetchIOCs fetches the IOC list from the configured source.
func (c *IOCCache) fetchIOCs() (*types.IOCDatabase, error) {
	resp, err := c.httpClient.Get(c.sourceURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return parseIOCCSV(resp.Body)
}

// parseIOCCSV parses the CSV IOC data.
// Expected format: package_name,package_versions,sources
func parseIOCCSV(r io.Reader) (*types.IOCDatabase, error) {
	reader := csv.NewReader(bufio.NewReader(r))

	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV header: %w", err)
	}

	cols := findIOCColumns(header)
	if cols.name == -1 || cols.version == -1 {
		return nil, fmt.Errorf("CSV missing required columns (package_name, package_versions)")
	}

	packages := make(map[string]types.CompromisedPackage)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		pkg := parseIOCRecord(record, cols)
		if pkg != nil {
			packages[pkg.Name] = *pkg
		}
	}

	return &types.IOCDatabase{
		Packages:    packages,
		LastUpdated: time.Now().UTC().Format(time.RFC3339),
		Sources:     []string{"datadog"},
	}, nil
}

// iocColumns holds the column indices for IOC CSV parsing.
type iocColumns struct {
	name, version, source int
}

// findIOCColumns locates the required columns in the CSV header.
func findIOCColumns(header []string) iocColumns {
	return iocColumns{
		name:    findColumnIndex(header, "package_name", "name", "package"),
		version: findColumnIndex(header, "package_versions", "version", "compromised_version"),
		source:  findColumnIndex(header, "sources", "source", "reporter"),
	}
}

// parseIOCRecord parses a single CSV record into a CompromisedPackage.
func parseIOCRecord(record []string, cols iocColumns) *types.CompromisedPackage {
	if len(record) <= cols.name || len(record) <= cols.version {
		return nil
	}

	name := strings.TrimSpace(record[cols.name])
	versionsStr := strings.TrimSpace(record[cols.version])
	if name == "" || versionsStr == "" {
		return nil
	}

	var sources []string
	if cols.source != -1 && len(record) > cols.source {
		sources = splitAndTrim(record[cols.source])
	}

	return &types.CompromisedPackage{
		Name:     name,
		Versions: splitAndTrim(versionsStr),
		Sources:  sources,
		Campaign: "shai-hulud-v2",
	}
}

// splitAndTrim splits a comma-separated string and trims whitespace from each part.
func splitAndTrim(s string) []string {
	var result []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

// findColumnIndex finds the index of a column by possible names (case-insensitive).
func findColumnIndex(header []string, names ...string) int {
	for i, col := range header {
		col = strings.TrimSpace(col)
		for _, name := range names {
			if strings.EqualFold(col, name) {
				return i
			}
		}
	}
	return -1
}
