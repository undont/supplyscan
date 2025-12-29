// Package supplychain provides IOC fetching and supply chain detection.
package supplychain

import (
	"context"
	"net/http"
	"time"

	"github.com/seanhalberthal/supplyscan/internal/types"
)

// IOCSource represents a provider of IOC (Indicators of Compromise) data.
type IOCSource interface {
	// Name returns a unique identifier for this source (e.g., "datadog", "github").
	Name() string

	// Fetch retrieves IOC data from the upstream source.
	Fetch(ctx context.Context, client *http.Client) (*types.SourceData, error)

	// CacheTTL returns how long this source's data should be considered fresh.
	CacheTTL() time.Duration
}

// sourceStatus tracks the state of an individual IOC source.
type sourceStatus struct {
	// Name is the source identifier.
	Name string `json:"name"`

	// LastFetched is when data was last successfully retrieved.
	LastFetched string `json:"last_fetched"`

	// ETag is the HTTP ETag for cache validation (if supported).
	ETag string `json:"etag,omitempty"`

	// Success indicates whether the last fetch was successful.
	Success bool `json:"success"`

	// Error contains the error message if the last fetch failed.
	Error string `json:"error,omitempty"`

	// PackageCount is the number of packages from this source.
	PackageCount int `json:"package_count"`

	// CacheTTLHours is the cache TTL for this source in hours.
	CacheTTLHours int `json:"cache_ttl_hours"`
}
