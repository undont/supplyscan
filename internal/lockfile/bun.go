package lockfile

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/seanhalberthal/supplyscan/internal/jsonc"
	"github.com/seanhalberthal/supplyscan/internal/types"
)

// bunLockfile represents a parsed bun.lock file.
type bunLockfile struct {
	path string
	deps []types.Dependency
}

func (l *bunLockfile) Type() string {
	return "bun"
}

func (l *bunLockfile) Path() string {
	return l.path
}

func (l *bunLockfile) Dependencies() []types.Dependency {
	return l.deps
}

// bunLockfileJSON represents the structure of bun.lock.
// The format is JSONC (JSON with comments).
type bunLockfileJSON struct {
	LockfileVersion int                          `json:"lockfileVersion"`
	Packages        map[string][]json.RawMessage `json:"packages"`
}

// parseBun parses a bun.lock file.
func parseBun(path string) (Lockfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Strip JSONC comments
	data = jsonc.StripComments(data)

	var lockfile bunLockfileJSON
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, err
	}

	var deps []types.Dependency
	seen := make(map[string]bool)

	for key, entries := range lockfile.Packages {
		// Skip workspace entries
		if key == "" || strings.HasPrefix(key, "workspace:") {
			continue
		}

		// Parse each entry in the array
		for _, entry := range entries {
			name, version := parseBunEntry(key, entry)
			if name == "" || version == "" {
				continue
			}

			dedupKey := name + "@" + version
			if seen[dedupKey] {
				continue
			}
			seen[dedupKey] = true

			deps = append(deps, types.Dependency{
				Name:    name,
				Version: version,
			})
		}
	}

	return &bunLockfile{
		path: path,
		deps: deps,
	}, nil
}

// parseBunEntry extracts name and version from a bun.lock entry.
// The key format is "name@version" or "@scope/name@version".
// The entry can be a string (version) or an array with version as first element.
func parseBunEntry(key string, entry json.RawMessage) (name, version string) {
	// Try to extract version from entry
	var strEntry string
	if err := json.Unmarshal(entry, &strEntry); err == nil {
		// Entry is a string - this is the version/resolution
		version = extractBunVersion(strEntry)
	} else {
		// Entry might be an array
		var arrEntry []json.RawMessage
		if err := json.Unmarshal(entry, &arrEntry); err == nil && len(arrEntry) > 0 {
			// First element is the version/resolution
			if err := json.Unmarshal(arrEntry[0], &strEntry); err == nil {
				version = extractBunVersion(strEntry)
			}
		}
	}

	// Extract name from key
	name = extractBunPackageName(key)

	return name, version
}

// extractBunPackageName extracts the package name from a bun.lock key.
func extractBunPackageName(key string) string {
	// Handle scoped packages: @scope/name@version
	if strings.HasPrefix(key, "@") {
		// Find the second @ (version separator)
		rest := key[1:]
		if atIdx := strings.Index(rest, "@"); atIdx != -1 {
			return key[:atIdx+1]
		}
		return key // No version in key
	}

	// Regular package: name@version
	if atIdx := strings.Index(key, "@"); atIdx != -1 {
		return key[:atIdx]
	}
	return key
}

// extractBunVersion extracts a clean version from a bun resolution string.
// Format might be "4.17.21" or "lodash@4.17.21" or a URL.
func extractBunVersion(s string) string {
	// If it looks like a version number, return as-is
	if s != "" && (s[0] >= '0' && s[0] <= '9') {
		return s
	}

	// If it contains @, extract version after it
	if atIdx := strings.LastIndex(s, "@"); atIdx != -1 {
		return s[atIdx+1:]
	}

	return s
}
