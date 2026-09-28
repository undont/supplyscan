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
	return typeBun
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
	Workspaces      map[string]bunWorkspace      `json:"workspaces"`
	Packages        map[string][]json.RawMessage `json:"packages"`
}

// bunWorkspace is one entry of `workspaces`, keyed by path ("" is the root).
type bunWorkspace struct {
	Name                 string            `json:"name"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

// bunPackageMeta is the metadata object inside a `packages` entry.
type bunPackageMeta struct {
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
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

	devOnly := bunDevOnlyKeys(&lockfile)

	var deps []types.Dependency
	index := make(map[string]int)

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

		// one name@version can sit under several keys; it is dev only if every copy is
		dedupKey := name + "@" + version
		if i, ok := index[dedupKey]; ok {
			deps[i].Dev = deps[i].Dev && devOnly[key]
			continue
		}
		index[dedupKey] = len(deps)

		deps = append(deps, types.Dependency{
			Name:    name,
			Version: version,
			Dev:     devOnly[key],
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

// bunGraph walks `packages` the way bun resolves it: a dependency of the package
// at key "a/b" is the first of "a/b/dep", "a/dep", "dep" present in the map
type bunGraph struct {
	packages map[string][]json.RawMessage
}

// bunDevOnlyKeys returns the package keys reachable from some workspace's
// devDependencies but from no workspace's dependencies, optionalDependencies or
// peerDependencies. keys reachable from neither stay out, so they count as prod
func bunDevOnlyKeys(lockfile *bunLockfileJSON) map[string]bool {
	g := bunGraph{packages: lockfile.Packages}
	prod := make(map[string]bool)
	dev := make(map[string]bool)

	for path, ws := range lockfile.Workspaces {
		base := bunWorkspaceBase(path, ws.Name)
		for _, group := range []map[string]string{ws.Dependencies, ws.OptionalDependencies, ws.PeerDependencies} {
			g.visitAll(prod, base, group)
		}
		g.visitAll(dev, base, ws.DevDependencies)
	}

	devOnly := make(map[string]bool)
	for key := range dev {
		if !prod[key] {
			devOnly[key] = true
		}
	}
	return devOnly
}

// bunWorkspaceBase is the key path a workspace's own dependencies resolve from:
// "{name}/{dep}" before "{dep}" for a member, "{dep}" alone for the root
func bunWorkspaceBase(path, name string) []string {
	if path == "" || name == "" {
		return nil
	}
	return []string{name}
}

func (g *bunGraph) visitAll(seen map[string]bool, from []string, deps map[string]string) {
	for dep := range deps {
		if next, ok := g.resolve(from, dep); ok {
			g.visit(seen, next)
		}
	}
}

// visit marks the package at path and everything it depends on. a workspace
// entry stops the walk, since every workspace is already a root of its own
func (g *bunGraph) visit(seen map[string]bool, path []string) {
	key := strings.Join(path, "/")
	if seen[key] {
		return
	}
	seen[key] = true

	meta, ok := g.meta(key)
	if !ok {
		return
	}
	for _, group := range []map[string]string{meta.Dependencies, meta.OptionalDependencies, meta.PeerDependencies} {
		g.visitAll(seen, path, group)
	}
}

func (g *bunGraph) resolve(from []string, dep string) ([]string, bool) {
	for i := len(from); i >= 0; i-- {
		candidate := append(append([]string{}, from[:i]...), dep)
		if _, ok := g.packages[strings.Join(candidate, "/")]; ok {
			return candidate, true
		}
	}
	return nil, false
}

// meta returns the metadata object of a `packages` entry. its position depends
// on the resolution kind (npm, git, tarball), and workspace entries have none
func (g *bunGraph) meta(key string) (bunPackageMeta, bool) {
	entries := g.packages[key]
	if len(entries) < 2 {
		return bunPackageMeta{}, false
	}
	for _, raw := range entries[1:] {
		if len(raw) == 0 || raw[0] != '{' {
			continue
		}
		var meta bunPackageMeta
		if err := json.Unmarshal(raw, &meta); err != nil {
			return bunPackageMeta{}, false
		}
		return meta, true
	}
	return bunPackageMeta{}, false
}
