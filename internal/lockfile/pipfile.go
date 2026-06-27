package lockfile

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/undont/supplyscan/internal/types"
)

// pipfileLockfile represents a parsed Pipfile.lock file.
type pipfileLockfile struct {
	path string
	deps []types.Dependency
}

// pipfileLockJSON is the structure of Pipfile.lock: package maps keyed by name,
// with "default" holding runtime deps and "develop" holding dev deps.
type pipfileLockJSON struct {
	Default map[string]pipfilePackageJSON `json:"default"`
	Develop map[string]pipfilePackageJSON `json:"develop"`
}

// pipfilePackageJSON is a single Pipfile.lock entry. Pinned entries carry a
// version like "==2.0.1"; VCS/path entries omit it and are skipped.
type pipfilePackageJSON struct {
	Version string `json:"version"`
}

func (l *pipfileLockfile) Type() string {
	return "pipfile"
}

func (l *pipfileLockfile) Path() string {
	return l.path
}

func (l *pipfileLockfile) Dependencies() []types.Dependency {
	return l.deps
}

// parsePipfile parses a Pipfile.lock file.
func parsePipfile(path string) (Lockfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lock pipfileLockJSON
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	var deps []types.Dependency
	seen := make(map[string]bool)

	add := func(packages map[string]pipfilePackageJSON, dev bool) {
		for name, pkg := range packages {
			version := strings.TrimPrefix(strings.TrimSpace(pkg.Version), "==")
			// only exact pins are usable; ranges/wildcards/VCS can't match IOCs
			if version == "" || strings.ContainsAny(version, " ,<>=!~*") {
				continue
			}
			norm := types.NormalizePyPIName(name)
			key := norm + "@" + version
			if seen[key] {
				continue
			}
			seen[key] = true
			deps = append(deps, types.Dependency{
				Name:      norm,
				Version:   version,
				Ecosystem: types.EcosystemPyPI,
				Dev:       dev,
			})
		}
	}

	add(lock.Default, false)
	add(lock.Develop, true)

	return &pipfileLockfile{path: path, deps: deps}, nil
}
