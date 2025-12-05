package lockfile

import (
	"os"
	"strings"

	"github.com/seanhalberthal/supplyscan-mcp/internal/types"
	"gopkg.in/yaml.v3"
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
	LockfileVersion any                       `yaml:"lockfileVersion"`
	Packages        map[string]pnpmPackage    `yaml:"packages"`
	// v6+ format
	Snapshots       map[string]pnpmSnapshot   `yaml:"snapshots"`
}

type pnpmPackage struct {
	Resolution  pnpmResolution `yaml:"resolution"`
	Dev         bool           `yaml:"dev"`
	Optional    bool           `yaml:"optional"`
	// v6+ format includes version directly
	Version     string         `yaml:"version"`
}

type pnpmSnapshot struct {
	// v9 format
}

type pnpmResolution struct {
	Integrity string `yaml:"integrity"`
	Tarball   string `yaml:"tarball"`
}

// ParsePNPM parses a pnpm-lock.yaml file.
func ParsePNPM(path string) (Lockfile, error) {
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
// Formats vary by lockfile version:
//   - v5: "/lodash/4.17.21"
//   - v6+: "/lodash@4.17.21" or "lodash@4.17.21"
//   - Scoped: "/@babel/core@7.23.0" or "/@babel/core/7.23.0"
func parsePnpmPackageKey(key string, explicitVersion string) (name, version string) {
	// Remove leading slash if present
	key = strings.TrimPrefix(key, "/")

	// If explicit version is provided (v6+ format), use it
	if explicitVersion != "" {
		// Extract name from key (before @version or /version)
		if atIdx := strings.LastIndex(key, "@"); atIdx > 0 {
			// Handle scoped packages: @scope/pkg@version
			if strings.HasPrefix(key, "@") {
				// Find second @ (version separator)
				rest := key[1:]
				if innerAt := strings.Index(rest, "@"); innerAt != -1 {
					name = key[:innerAt+1]
				}
			} else {
				name = key[:atIdx]
			}
		}
		return name, explicitVersion
	}

	// v5 format: /package/version or /@scope/package/version
	if strings.HasPrefix(key, "@") {
		// Scoped package: @scope/package/version
		parts := strings.Split(key, "/")
		if len(parts) >= 3 {
			name = parts[0] + "/" + parts[1]
			version = parts[2]
			// Handle additional path segments (peer deps)
			if underscoreIdx := strings.Index(version, "_"); underscoreIdx != -1 {
				version = version[:underscoreIdx]
			}
		}
	} else {
		// Regular package: package/version or package@version
		if atIdx := strings.LastIndex(key, "@"); atIdx > 0 {
			name = key[:atIdx]
			version = key[atIdx+1:]
		} else {
			parts := strings.Split(key, "/")
			if len(parts) >= 2 {
				name = parts[0]
				version = parts[1]
			}
		}
		// Handle additional path segments (peer deps)
		if underscoreIdx := strings.Index(version, "_"); underscoreIdx != -1 {
			version = version[:underscoreIdx]
		}
	}

	return name, version
}