package lockfile

import (
	"strings"

	"github.com/undont/supplyscan/internal/types"
)

// uvLockfile represents a parsed uv.lock file.
type uvLockfile struct {
	path string
	deps []types.Dependency
}

func (l *uvLockfile) Type() string {
	return "uv"
}

func (l *uvLockfile) Path() string {
	return l.path
}

func (l *uvLockfile) Dependencies() []types.Dependency {
	return l.deps
}

// parseUv parses a uv.lock file: TOML [[package]] tables. uv.lock has no
// per-package dev marker (dev groups live in the project metadata), so every
// dependency is treated as non-dev. The workspace root is recorded as a package
// with an editable/virtual source and is skipped.
func parseUv(path string) (Lockfile, error) {
	deps, err := parseTOMLPackages(path, func(fields map[string]string) (types.Dependency, bool) {
		source := fields["source"]
		if strings.Contains(source, "editable") || strings.Contains(source, "virtual") {
			return types.Dependency{}, false
		}
		name := tomlUnquote(fields["name"])
		version := tomlUnquote(fields["version"])
		if name == "" || version == "" {
			return types.Dependency{}, false
		}
		return types.Dependency{
			Name:      types.NormalizePyPIName(name),
			Version:   version,
			Ecosystem: types.EcosystemPyPI,
		}, true
	})
	if err != nil {
		return nil, err
	}

	return &uvLockfile{path: path, deps: deps}, nil
}
