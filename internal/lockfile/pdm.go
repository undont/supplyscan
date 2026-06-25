package lockfile

import (
	"github.com/undont/supplyscan/internal/types"
)

// pdmLockfile represents a parsed pdm.lock file.
type pdmLockfile struct {
	path string
	deps []types.Dependency
}

func (l *pdmLockfile) Type() string {
	return "pdm"
}

func (l *pdmLockfile) Path() string {
	return l.path
}

func (l *pdmLockfile) Dependencies() []types.Dependency {
	return l.deps
}

// parsePdm parses a pdm.lock file: TOML [[package]] tables with a `groups`
// array; membership of the "dev" group marks a development dependency.
func parsePdm(path string) (Lockfile, error) {
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
			Dev:       tomlArrayContains(fields["groups"], "dev"),
		}, true
	})
	if err != nil {
		return nil, err
	}

	return &pdmLockfile{path: path, deps: deps}, nil
}
