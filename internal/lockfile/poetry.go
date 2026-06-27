package lockfile

import (
	"github.com/undont/supplyscan/internal/types"
)

// poetryLockfile represents a parsed poetry.lock file.
type poetryLockfile struct {
	path string
	deps []types.Dependency
}

func (l *poetryLockfile) Type() string {
	return "poetry"
}

func (l *poetryLockfile) Path() string {
	return l.path
}

func (l *poetryLockfile) Dependencies() []types.Dependency {
	return l.deps
}

// parsePoetry parses a poetry.lock file: TOML [[package]] tables with a
// `category` field that is "dev" for development dependencies.
func parsePoetry(path string) (Lockfile, error) {
	deps, err := parseTOMLPackages(path, func(fields map[string]string) (types.Dependency, bool) {
		name := tomlUnquote(fields["name"])
		version := tomlUnquote(fields["version"])
		if name == "" || version == "" {
			return types.Dependency{}, false
		}
		return types.Dependency{
			Name:      types.NormalizePyPIName(name),
			Version:   version,
			Ecosystem: types.EcosystemPyPI,
			Dev:       tomlUnquote(fields["category"]) == "dev",
		}, true
	})
	if err != nil {
		return nil, err
	}

	return &poetryLockfile{path: path, deps: deps}, nil
}
