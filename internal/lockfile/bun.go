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
//
// Each entry in `packages` is a positional array:
//
//	[ "name@version", "registry", { metadata }, "sha512-..." ]
//
// Only position 0 (the resolution string) carries the version. The other
// slots are registry URL, peer-dep metadata, and the integrity hash —
// none of which should be treated as additional versions.
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
		if len(entries) == 0 {
			continue
		}

		name, version := parseBunResolution(key, entries[0])
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

	return &bunLockfile{
		path: path,
		deps: deps,
	}, nil
}

// parseBunResolution extracts name and version from the first element of a
// bun.lock package entry. The resolution is a string like "name@version" or
// "@scope/name@version"; the key supplies the canonical package name.
func parseBunResolution(key string, raw json.RawMessage) (name, version string) {
	var resolution string
	if err := json.Unmarshal(raw, &resolution); err != nil {
		return "", ""
	}
	return extractBunPackageName(key), extractBunVersion(resolution)
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
