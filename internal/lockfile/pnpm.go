package lockfile

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/seanhalberthal/supplyscan/internal/types"
)

// pnpmLockfile represents a parsed pnpm-lock.yaml file.
type pnpmLockfile struct {
	path string
	deps []types.Dependency
}

func (l *pnpmLockfile) Type() string {
	return "pnpm"
}

func (l *pnpmLockfile) Path() string {
	return l.path
}

func (l *pnpmLockfile) Dependencies() []types.Dependency {
	return l.deps
}

// pnpmLockfileYAML represents the structure of pnpm-lock.yaml.
type pnpmLockfileYAML struct {
	LockfileVersion any                    `yaml:"lockfileVersion"`
	Packages        map[string]pnpmPackage `yaml:"packages"`
	// v6+ format
	Snapshots map[string]pnpmSnapshot `yaml:"snapshots"`
}

type pnpmPackage struct {
	Resolution pnpmResolution `yaml:"resolution"`
	Dev        bool           `yaml:"dev"`
	Optional   bool           `yaml:"optional"`
	// v6+ format includes version directly
	Version string `yaml:"version"`
}

type pnpmSnapshot struct {
	// v9 format
}

type pnpmResolution struct {
	Integrity string `yaml:"integrity"`
	Tarball   string `yaml:"tarball"`
}

// parsePNPM parses a pnpm-lock.yaml file.
func parsePNPM(path string) (Lockfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lockfile pnpmLockfileYAML
	if err := yaml.Unmarshal(data, &lockfile); err != nil {
		return nil, err
	}

	var deps []types.Dependency
	seen := make(map[string]bool)

	for key, pkg := range lockfile.Packages {
		name, version := parsePnpmPackageKey(key, pkg.Version)
		if name == "" || version == "" {
			continue
		}

		dedupKey := name + "@" + version
		if seen[dedupKey] {
			continue
		}
		seen[dedupKey] = true

		deps = append(deps, types.Dependency{
			Name:     name,
			Version:  version,
			Dev:      pkg.Dev,
			Optional: pkg.Optional,
		})
	}

	return &pnpmLockfile{
		path: path,
		deps: deps,
	}, nil
}

// parsePnpmPackageKey extracts name and version from a pnpm package key.
// Formats vary by Lockfile version:
//   - v5: "/lodash/4.17.21"
//   - v6+: "/lodash@4.17.21" or "lodash@4.17.21"
//   - Scoped: "/@babel/core@7.23.0" or "/@babel/core/7.23.0"
func parsePnpmPackageKey(key, explicitVersion string) (name, version string) {
	key = strings.TrimPrefix(key, "/")

	if explicitVersion != "" {
		return extractPnpmName(key), explicitVersion
	}

	name, version = parsePnpmV5Key(key)
	return name, stripPeerDeps(version)
}

// extractPnpmName extracts the package name from a pnpm key (v6+ format with explicit version).
func extractPnpmName(key string) string {
	atIdx := strings.LastIndex(key, "@")
	if atIdx <= 0 {
		return ""
	}

	// Scoped package: @scope/pkg@version - find second @
	if strings.HasPrefix(key, "@") {
		if innerAt := strings.Index(key[1:], "@"); innerAt != -1 {
			return key[:innerAt+1]
		}
		return ""
	}

	return key[:atIdx]
}

// parsePnpmV5Key parses v5 format: /package/version or /@scope/package/version
func parsePnpmV5Key(key string) (name, version string) {
	// For scoped packages in v6+ format: @scope/pkg@version
	if strings.HasPrefix(key, "@") {
		// Find the @ that separates name from version (not the scope @)
		slashIdx := strings.Index(key, "/")
		if slashIdx == -1 {
			return "", ""
		}
		// Look for @ after the slash
		rest := key[slashIdx+1:]
		atIdx := strings.Index(rest, "@")
		if atIdx != -1 {
			// v6+ format: @scope/pkg@version
			return key[:slashIdx+1+atIdx], rest[atIdx+1:]
		}
		// v5 format: @scope/pkg/version
		parts := strings.Split(key, "/")
		if len(parts) >= 3 {
			return parts[0] + "/" + parts[1], parts[2]
		}
		return "", ""
	}

	// Non-scoped packages
	// Check if it's v5 format (pkg/version) vs v6+ format (pkg@version)
	slashIdx := strings.Index(key, "/")
	atIdx := strings.Index(key, "@")

	// If there's a slash before any @, it's v5 format
	if slashIdx != -1 && (atIdx == -1 || slashIdx < atIdx) {
		parts := strings.Split(key, "/")
		if len(parts) >= 2 {
			return parts[0], parts[1]
		}
		return "", ""
	}

	// v6+ format: pkg@version
	if atIdx > 0 {
		return key[:atIdx], key[atIdx+1:]
	}

	return "", ""
}

// stripPeerDeps removes the peer dependency suffix (e.g., "1.0.0_peer" -> "1.0.0").
func stripPeerDeps(version string) string {
	if idx := strings.Index(version, "_"); idx != -1 {
		return version[:idx]
	}
	return version
}
