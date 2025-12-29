package lockfile

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/seanhalberthal/supplyscan/internal/types"
)

// yarnBerryLockfile represents a parsed yarn.lock v2+ (berry) file.
type yarnBerryLockfile struct {
	path string
	deps []types.Dependency
}

func (l *yarnBerryLockfile) Type() string {
	return "yarn-berry"
}

func (l *yarnBerryLockfile) Path() string {
	return l.path
}

func (l *yarnBerryLockfile) Dependencies() []types.Dependency {
	return l.deps
}

// yarnBerryEntry represents a single entry in yarn berry Lockfile.
type yarnBerryEntry struct {
	Version    string `yaml:"version"`
	Resolution string `yaml:"resolution"`
}

// parseYarnBerry parses a yarn.lock v2+ (berry) file.
func parseYarnBerry(path string) (Lockfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Parse the YAML
	var lockfile map[string]yarnBerryEntry
	if err := yaml.Unmarshal(data, &lockfile); err != nil {
		return nil, err
	}

	var deps []types.Dependency
	seen := make(map[string]bool)

	for key, entry := range lockfile {
		// Skip metadata entry
		if key == "__metadata" {
			continue
		}

		name := extractBerryPackageName(key)
		if name == "" {
			continue
		}

		// Skip workspace packages
		if strings.HasPrefix(entry.Resolution, "workspace:") {
			continue
		}

		// Deduplicate
		dedupKey := name + "@" + entry.Version
		if seen[dedupKey] {
			continue
		}
		seen[dedupKey] = true

		deps = append(deps, types.Dependency{
			Name:    name,
			Version: entry.Version,
		})
	}

	return &yarnBerryLockfile{
		path: path,
		deps: deps,
	}, nil
}

// extractBerryPackageName extracts the package name from a yarn berry key.
// Examples:
//   - "lodash@npm:^4.17.0"
//   - "@babel/core@npm:^7.0.0"
//   - "lodash@npm:^4.17.0, lodash@npm:^4.17.21"
func extractBerryPackageName(key string) string {
	// Handle multiple specifiers (take the first one)
	if idx := strings.Index(key, ","); idx != -1 {
		key = key[:idx]
	}

	key = strings.TrimSpace(key)

	// Remove quotes if present
	key = strings.Trim(key, "\"")

	// Find the @npm: or @workspace: part
	var name string
	if strings.HasPrefix(key, "@") {
		// Scoped package: @scope/name@npm:version
		// Find the second @ which has the protocol
		rest := key[1:]
		atIdx := strings.Index(rest, "@")
		if atIdx != -1 {
			name = key[:atIdx+1]
		}
	} else {
		// Regular package: name@npm:version
		atIdx := strings.Index(key, "@")
		if atIdx != -1 {
			name = key[:atIdx]
		}
	}

	return name
}

// parseYarn detects the yarn format and parses accordingly.
func parseYarn(path string) (Lockfile, error) {
	isClassic, err := isYarnClassic(path)
	if err != nil {
		return nil, err
	}

	if isClassic {
		return parseYarnClassic(path)
	}
	return parseYarnBerry(path)
}
