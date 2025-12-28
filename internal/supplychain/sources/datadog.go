// Package sources provides IOC source implementations.
package sources

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/seanhalberthal/supplyscan/internal/types"
)

const (
	// defaultDataDogURL is the default URL for DataDog's consolidated IOC list.
	defaultDataDogURL = "https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/shai-hulud-2.0/consolidated_iocs.csv"

	// dataDogCacheTTL is the cache TTL for DataDog IOCs (6 hours).
	dataDogCacheTTL = 6 * time.Hour

	// dataDogCampaign is the campaign identifier for DataDog IOCs.
	dataDogCampaign = "shai-hulud-v2"

	// dataDogSourceName is the source identifier for DataDog.
	dataDogSourceName = "datadog"
)

// DataDogSource fetches IOC data from DataDog's consolidated IOC list.
type DataDogSource struct {
	url string
}

// DataDogSourceOption configures a DataDogSource.
type DataDogSourceOption func(*DataDogSource)

// WithDataDogURL sets a custom URL for the DataDog source.
func WithDataDogURL(url string) DataDogSourceOption {
	return func(s *DataDogSource) {
		s.url = url
	}
}

// NewDataDogSource creates a new DataDog IOC source.
func NewDataDogSource(opts ...DataDogSourceOption) *DataDogSource {
	s := &DataDogSource{
		url: defaultDataDogURL,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Name returns the source identifier.
func (s *DataDogSource) Name() string {
	return dataDogSourceName
}

// CacheTTL returns how long this source's data should be cached.
func (s *DataDogSource) CacheTTL() time.Duration {
	return dataDogCacheTTL
}

// Fetch retrieves IOC data from the DataDog source.
func (s *DataDogSource) Fetch(ctx context.Context, client *http.Client) (*types.SourceData, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch IOCs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	packages, err := parseDataDogCSV(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSV: %w", err)
	}

	return &types.SourceData{
		Source:    s.Name(),
		Campaign:  dataDogCampaign,
		Packages:  packages,
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// parseDataDogCSV parses the DataDog CSV IOC data.
// Expected format: package_name,package_versions,sources
func parseDataDogCSV(r io.Reader) (map[string]types.SourcePackage, error) {
	reader := csv.NewReader(bufio.NewReader(r))

	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV header: %w", err)
	}

	cols := findCSVColumns(header)
	if cols.name == -1 || cols.version == -1 {
		return nil, fmt.Errorf("CSV missing required columns (package_name, package_versions)")
	}

	packages := make(map[string]types.SourcePackage)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		pkg := parseCSVRecord(record, cols)
		if pkg != nil {
			packages[pkg.Name] = *pkg
		}
	}

	return packages, nil
}

// csvColumns holds the column indices for CSV parsing.
type csvColumns struct {
	name, version, source int
}

// findCSVColumns locates the required columns in the CSV header.
func findCSVColumns(header []string) csvColumns {
	return csvColumns{
		name:    findColumnIndex(header, "package_name", "name", "package"),
		version: findColumnIndex(header, "package_versions", "version", "compromised_version"),
		source:  findColumnIndex(header, "sources", "source", "reporter"),
	}
}

// parseCSVRecord parses a single CSV record into a SourcePackage.
func parseCSVRecord(record []string, cols csvColumns) *types.SourcePackage {
	if len(record) <= cols.name || len(record) <= cols.version {
		return nil
	}

	name := strings.TrimSpace(record[cols.name])
	versionsStr := strings.TrimSpace(record[cols.version])
	if name == "" || versionsStr == "" {
		return nil
	}

	return &types.SourcePackage{
		Name:     name,
		Versions: splitAndTrim(versionsStr),
		Severity: "critical", // All Shai-Hulud compromises are critical
	}
}

// splitAndTrim splits a comma-separated string and trims whitespace.
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
