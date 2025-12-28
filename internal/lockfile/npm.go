package lockfile

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/seanhalberthal/supplyscan/internal/types"
)

// npmLockfile represents a parsed package-lock.json or npm-shrinkwrap.json.
type npmLockfile struct {
	path string
	deps []types.Dependency
}

// npmLockfileJSON is the JSON structure of package-lock.json (v2/v3).
type npmLockfileJSON struct {
	Name            string                    `json:"name"`
	Version         string                    `json:"version"`
	LockfileVersion int                       `json:"lockfileVersion"`
	Packages        map[string]npmPackageJSON `json:"packages"`
	// v1 format uses "dependencies" instead of "packages"
	Dependencies map[string]npmDependencyJSON `json:"dependencies"`
}

type npmPackageJSON struct {
	Version   string            `json:"version"`
	Resolved  string            `json:"resolved"`
	Integrity string            `json:"integrity"`
	Dev       bool              `json:"dev"`
	Optional  bool              `json:"optional"`
	Requires  map[string]string `json:"requires"`
}

type npmDependencyJSON struct {
	Version      string                       `json:"version"`
	Resolved     string                       `json:"resolved"`
	Integrity    string                       `json:"integrity"`
	Dev          bool                         `json:"dev"`
	Optional     bool                         `json:"optional"`
	Requires     map[string]string            `json:"requires"`
	Dependencies map[string]npmDependencyJSON `json:"dependencies"`
}

func (l *npmLockfile) Type() string {
	return "npm"
}

func (l *npmLockfile) Path() string {
	return l.path
}

func (l *npmLockfile) Dependencies() []types.Dependency {
	return l.deps
}

// parseNPM parses a package-lock.json or npm-shrinkwrap.json file.
func parseNPM(path string) (Lockfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lockfile npmLockfileJSON
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, err
	}

	var deps []types.Dependency

	// v2/v3 format uses "packages" map
	if lockfile.LockfileVersion >= 2 && len(lockfile.Packages) > 0 {
		deps = parseNPMPackages(lockfile.Packages)
	} else if len(lockfile.Dependencies) > 0 {
		// v1 format uses "dependencies" map
		deps = parseNPMDependencies(lockfile.Dependencies)
	}

	return &npmLockfile{
		path: path,
		deps: deps,
	}, nil
}

// parseNPMPackages extracts dependencies from the v2/v3 packages map.
func parseNPMPackages(packages map[string]npmPackageJSON) []types.Dependency {
	var deps []types.Dependency
	seen := make(map[string]bool)

	for pkgPath, pkg := range packages {
		// Skip the root package (empty path)
		if pkgPath == "" {
			continue
		}

		// Extract package name from path
		// Path format: "node_modules/@scope/package" or "node_modules/package"
		name := extractPackageName(pkgPath)
		if name == "" {
			continue
		}

		// Deduplicate by name@version
		key := name + "@" + pkg.Version
		if seen[key] {
			continue
		}
		seen[key] = true

		deps = append(deps, types.Dependency{
			Name:     name,
			Version:  pkg.Version,
			Dev:      pkg.Dev,
			Optional: pkg.Optional,
		})
	}

	return deps
}

// parseNPMDependencies extracts dependencies from the v1 dependencies map.
func parseNPMDependencies(dependencies map[string]npmDependencyJSON) []types.Dependency {
	var deps []types.Dependency
	seen := make(map[string]bool)

	var walk func(name string, dep npmDependencyJSON)
	walk = func(name string, dep npmDependencyJSON) {
		key := name + "@" + dep.Version
		if seen[key] {
			return
		}
		seen[key] = true

		deps = append(deps, types.Dependency{
			Name:     name,
			Version:  dep.Version,
			Dev:      dep.Dev,
			Optional: dep.Optional,
		})

		// Recursively process nested dependencies
		for nestedName, nestedDep := range dep.Dependencies {
			walk(nestedName, nestedDep)
		}
	}

	for name, dep := range dependencies {
		walk(name, dep)
	}

	return deps
}

// extractPackageName extracts the package name from a node_modules path.
func extractPackageName(path string) string {
	// Remove "node_modules/" prefix (possibly nested)
	parts := strings.Split(path, "node_modules/")
	if len(parts) < 2 {
		return ""
	}

	// Get the last segment after node_modules/
	name := parts[len(parts)-1]

	// Handle scoped packages (@scope/package)
	if strings.HasPrefix(name, "@") {
		// Include the scope and package name
		segments := strings.SplitN(name, "/", 3)
		if len(segments) >= 2 {
			return segments[0] + "/" + segments[1]
		}
	}

	// Regular package - just the first segment
	segments := strings.SplitN(name, "/", 2)
	return segments[0]
}
