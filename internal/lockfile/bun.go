package lockfile

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/undont/supplyscan/internal/jsonc"
	"github.com/undont/supplyscan/internal/types"
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
// "@scope/name@version".
//
// The resolution — not the key — is the source of truth for the name. Bun
// stores the hoisted copy of a package under a flat key ("postcss") but any
// version that could not be hoisted under a "parent/child" path key
// ("@expo/metro-config/postcss"). Deriving the name from the key mangles those
// nested entries, so they match no real npm package and silently drop out of
// the audit. The resolution carries the true name in every case.
func parseBunResolution(key string, raw json.RawMessage) (name, version string) {
	var resolution string
	if err := json.Unmarshal(raw, &resolution); err != nil {
		return "", ""
	}
	if n, v := splitBunResolution(resolution); n != "" {
		return n, v
	}
	// Fall back to the key for resolutions that are not in "name@version" form
	// (bare versions, URLs, git refs).
	return extractBunPackageName(key), extractBunVersion(resolution)
}

// splitBunResolution splits a "name@version" / "@scope/name@version" resolution
// into its package name and version. The version follows the final "@"; for a
// scoped name the leading "@" is the scope marker, not a separator. Returns
// empty strings unless the trailing segment looks like a semantic version, so
// URL, git, and alias resolutions fall through to key-based extraction.
func splitBunResolution(resolution string) (name, version string) {
	at := strings.LastIndex(resolution, "@")
	if at <= 0 {
		return "", ""
	}
	v := resolution[at+1:]
	if v == "" || v[0] < '0' || v[0] > '9' {
		return "", ""
	}
	return resolution[:at], v
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
	if before, _, ok := strings.Cut(key, "@"); ok {
		return before
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
