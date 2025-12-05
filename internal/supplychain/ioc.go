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

const (
	// DataDog consolidated IOC list URL
	IOCSourceURL = "https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/shai-hulud-2.0/consolidated_iocs.csv"

	// Cache TTL in hours
	DefaultCacheTTL = 6
)

// IOCCache manages the local IOC database cache.
type IOCCache struct {
	cacheDir string
}

// NewIOCCache creates a new IOC cache manager.
func NewIOCCache() (*IOCCache, error) {
	cacheDir, err := getCacheDir()
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	return &IOCCache{cacheDir: cacheDir}, nil
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

// Save saves the IOC database to cache.
func (c *IOCCache) Save(db *types.IOCDatabase) error {
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}

	path := filepath.Join(c.cacheDir, "iocs.json")
	return os.WriteFile(path, data, 0644)
}

// LoadMeta loads the cache metadata.
func (c *IOCCache) LoadMeta() (*types.IOCMeta, error) {
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

// SaveMeta saves the cache metadata.
func (c *IOCCache) SaveMeta(meta *types.IOCMeta) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}

	path := filepath.Join(c.cacheDir, "meta.json")
	return os.WriteFile(path, data, 0644)
}

// IsStale checks if the cache is older than the TTL.
func (c *IOCCache) IsStale() bool {
	meta, err := c.LoadMeta()
	if err != nil || meta == nil {
		return true
	}

	lastUpdated, err := time.Parse(time.RFC3339, meta.LastUpdated)
	if err != nil {
		return true
	}

	return time.Since(lastUpdated) > time.Duration(DefaultCacheTTL)*time.Hour
}

// CacheAgeHours returns the age of the cache in hours.
func (c *IOCCache) CacheAgeHours() int {
	meta, err := c.LoadMeta()
	if err != nil || meta == nil {
		return -1
	}

	lastUpdated, err := time.Parse(time.RFC3339, meta.LastUpdated)
	if err != nil {
		return -1
	}

	return int(time.Since(lastUpdated).Hours())
}

// Refresh fetches the latest IOC data and updates the cache.
func (c *IOCCache) Refresh(force bool) (*types.RefreshResult, error) {
	if !force && !c.IsStale() {
		// Cache is still fresh
		meta, _ := c.LoadMeta()
		return &types.RefreshResult{
			Updated:       false,
			PackagesCount: meta.PackageCount,
			VersionsCount: meta.VersionCount,
			CacheAgeHours: c.CacheAgeHours(),
		}, nil
	}

	// Fetch from upstream
	db, err := fetchIOCs()
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
	if err := c.Save(db); err != nil {
		return nil, fmt.Errorf("failed to save IOC cache: %w", err)
	}

	// Update metadata
	meta := &types.IOCMeta{
		LastUpdated:  time.Now().UTC().Format(time.RFC3339),
		PackageCount: packageCount,
		VersionCount: versionCount,
	}
	if err := c.SaveMeta(meta); err != nil {
		return nil, fmt.Errorf("failed to save cache metadata: %w", err)
	}

	return &types.RefreshResult{
		Updated:       true,
		PackagesCount: packageCount,
		VersionsCount: versionCount,
		CacheAgeHours: 0,
	}, nil
}

// fetchIOCs fetches the IOC list from DataDog's GitHub.
func fetchIOCs() (*types.IOCDatabase, error) {
	resp, err := http.Get(IOCSourceURL)
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
// Expected format: package_name,version,source,...
func parseIOCCSV(r io.Reader) (*types.IOCDatabase, error) {
	packages := make(map[string]types.CompromisedPackage)

	reader := csv.NewReader(bufio.NewReader(r))

	// Read header
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV header: %w", err)
	}

	// Find column indices
	nameIdx := findColumnIndex(header, "package_name", "name", "package")
	versionIdx := findColumnIndex(header, "version", "compromised_version")
	sourceIdx := findColumnIndex(header, "source", "reporter")

	if nameIdx == -1 || versionIdx == -1 {
		return nil, fmt.Errorf("CSV missing required columns (package_name, version)")
	}

	// Read data rows
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // Skip malformed rows
		}

		if len(record) <= nameIdx || len(record) <= versionIdx {
			continue
		}

		name := strings.TrimSpace(record[nameIdx])
		version := strings.TrimSpace(record[versionIdx])

		if name == "" || version == "" {
			continue
		}

		source := "unknown"
		if sourceIdx != -1 && len(record) > sourceIdx {
			source = strings.TrimSpace(record[sourceIdx])
		}

		// Add to or update package entry
		pkg, exists := packages[name]
		if !exists {
			pkg = types.CompromisedPackage{
				Name:     name,
				Versions: []string{},
				Sources:  []string{},
				Campaign: "shai-hulud-v2",
			}
		}

		// Add version if not already present
		if !contains(pkg.Versions, version) {
			pkg.Versions = append(pkg.Versions, version)
		}

		// Add source if not already present
		if source != "" && !contains(pkg.Sources, source) {
			pkg.Sources = append(pkg.Sources, source)
		}

		packages[name] = pkg
	}

	return &types.IOCDatabase{
		Packages:    packages,
		LastUpdated: time.Now().UTC().Format(time.RFC3339),
		Sources:     []string{"datadog"},
	}, nil
}

// findColumnIndex finds the index of a column by possible names.
func findColumnIndex(header []string, names ...string) int {
	for i, col := range header {
		col = strings.ToLower(strings.TrimSpace(col))
		for _, name := range names {
			if col == name {
				return i
			}
		}
	}
	return -1
}

// contains checks if a slice contains a string.
func contains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}