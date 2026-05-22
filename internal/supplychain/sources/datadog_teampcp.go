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
	// defaultDataDogTeamPCPURL is DataDog's IOC list for the TeamPCP campaign
	// (Mini Shai-Hulud and related self-spreading npm worms).
	defaultDataDogTeamPCPURL = "https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/teampcp/iocs.csv"

	// dataDogTeamPCPCacheTTL matches the standard DataDog cache TTL.
	dataDogTeamPCPCacheTTL = 6 * time.Hour

	// dataDogTeamPCPCampaign is the campaign identifier for TeamPCP IOCs.
	dataDogTeamPCPCampaign = "mini-shai-hulud-teampcp"

	// dataDogTeamPCPSourceName is the source identifier (must be unique to get its own cache file).
	dataDogTeamPCPSourceName = "datadog-teampcp"

	// teamPCPNpmArtefactType is the artefact_type value for npm packages in the CSV.
	teamPCPNpmArtefactType = "npm package"
)

// DataDogTeamPCPSource fetches the DataDog TeamPCP IOC list, which spans multiple
// ecosystems (npm, PyPI, Docker). Only npm package rows are retained.
type DataDogTeamPCPSource struct {
	url string
}

// DataDogTeamPCPSourceOption configures a DataDogTeamPCPSource.
type DataDogTeamPCPSourceOption func(*DataDogTeamPCPSource)

// WithDataDogTeamPCPURL sets a custom URL (mostly for tests).
func WithDataDogTeamPCPURL(url string) DataDogTeamPCPSourceOption {
	return func(s *DataDogTeamPCPSource) {
		s.url = url
	}
}

// NewDataDogTeamPCPSource creates a new DataDog TeamPCP IOC source.
func NewDataDogTeamPCPSource(opts ...DataDogTeamPCPSourceOption) *DataDogTeamPCPSource {
	s := &DataDogTeamPCPSource{url: defaultDataDogTeamPCPURL}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Name returns the source identifier.
func (s *DataDogTeamPCPSource) Name() string {
	return dataDogTeamPCPSourceName
}

// CacheTTL returns how long this source's data should be cached.
func (s *DataDogTeamPCPSource) CacheTTL() time.Duration {
	return dataDogTeamPCPCacheTTL
}

// Fetch retrieves the TeamPCP IOC list and filters it down to npm packages.
func (s *DataDogTeamPCPSource) Fetch(ctx context.Context, client *http.Client) (*types.SourceData, error) {
	return fetchCSVSource(ctx, client, s.url, s.Name(), dataDogTeamPCPCampaign, parseDataDogTeamPCPCSV)
}

// teamPCPColumns holds the column indices needed to parse a TeamPCP row.
type teamPCPColumns struct {
	artefact, name, version int
}

// parseDataDogTeamPCPCSV parses the TeamPCP CSV and keeps only npm rows.
// Expected schema: artefact_type,name,affected_versions (column name uses
// the US spelling in the upstream data — see literal below).
func parseDataDogTeamPCPCSV(r io.Reader) (map[string]types.SourcePackage, error) {
	reader := csv.NewReader(bufio.NewReader(r))

	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV header: %w", err)
	}

	cols := teamPCPColumns{
		artefact: findColumnIndex(header, "artifact_type", "artefact_type", "type"), //nolint:misspell // upstream CSV column name
		name:     findColumnIndex(header, "name", "package_name", "package"),
		version:  findColumnIndex(header, "affected_versions", "package_versions", "versions", "version"),
	}
	if cols.artefact == -1 || cols.name == -1 || cols.version == -1 {
		return nil, fmt.Errorf("CSV missing required columns (artefact_type, name, affected_versions)")
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
		if pkg := parseTeamPCPRow(record, cols); pkg != nil {
			packages[pkg.Name] = *pkg
		}
	}
	return packages, nil
}

// parseTeamPCPRow turns a single CSV record into a SourcePackage, or returns
// nil if the row should be skipped (non-npm artefact, malformed, or empty).
func parseTeamPCPRow(record []string, cols teamPCPColumns) *types.SourcePackage {
	if len(record) <= cols.artefact || len(record) <= cols.name || len(record) <= cols.version {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(record[cols.artefact]), teamPCPNpmArtefactType) {
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
		Severity: "critical",
	}
}
