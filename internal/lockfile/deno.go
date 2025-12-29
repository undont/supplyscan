package lockfile

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/seanhalberthal/supplyscan/internal/types"
)

// denoLockfile represents a parsed deno.lock file.
type denoLockfile struct {
	path string
	deps []types.Dependency
}

func (l *denoLockfile) Type() string {
	return "deno"
}

func (l *denoLockfile) Path() string {
	return l.path
}

func (l *denoLockfile) Dependencies() []types.Dependency {
	return l.deps
}

// denoLockfileJSON represents the structure of deno.lock.
type denoLockfileJSON struct {
	Version  string       `json:"version"`
	Packages denoPackages `json:"packages"`
}

type denoPackages struct {
	// npm packages are under the "npm" key
	NPM map[string]denoNPMPackage `json:"npm"`
}

type denoNPMPackage struct {
	Integrity    string            `json:"integrity"`
	Dependencies map[string]string `json:"dependencies"`
}

// parseDeno parses a deno.lock file, extracting npm dependencies.
func parseDeno(path string) (Lockfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lockfile denoLockfileJSON
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, err
	}

	var deps []types.Dependency
	seen := make(map[string]bool)

	for key := range lockfile.Packages.NPM {
		name, version := parseDenoNPMKey(key)
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

	return &denoLockfile{
		path: path,
		deps: deps,
	}, nil
}

// parseDenoNPMKey extracts name and version from a deno npm package key.
// Format: "package@version" or "@scope/package@version"
func parseDenoNPMKey(key string) (name, version string) {
	// Handle scoped packages: @scope/name@version
	if strings.HasPrefix(key, "@") {
		// Find the second @ (version separator)
		rest := key[1:]
		if atIdx := strings.Index(rest, "@"); atIdx != -1 {
			name = key[:atIdx+1]
			version = key[atIdx+2:]
		}
	} else {
		// Regular package: name@version
		name, version, _ = strings.Cut(key, "@")
	}

	// Clean up version (remove any suffix like _peer)
	if underscoreIdx := strings.Index(version, "_"); underscoreIdx != -1 {
		version = version[:underscoreIdx]
	}

	return name, version
}
