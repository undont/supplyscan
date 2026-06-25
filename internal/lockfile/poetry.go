package lockfile

import (
	"bufio"
	"os"
	"strings"

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

// parsePoetry parses a poetry.lock file. The format is TOML with a sequence of
// [[package]] tables; we scan line by line for name/version rather than pull in
// a TOML dependency, keeping supplyscan's own dependency surface minimal.
func parsePoetry(path string) (Lockfile, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []types.Dependency
	seen := make(map[string]bool)

	var inPackage bool
	var name, version, category string

	flush := func() {
		if name == "" || version == "" {
			return
		}
		norm := types.NormalizePyPIName(name)
		key := norm + "@" + version
		if !seen[key] {
			seen[key] = true
			deps = append(deps, types.Dependency{
				Name:      norm,
				Version:   version,
				Ecosystem: types.EcosystemPyPI,
				Dev:       category == "dev",
			})
		}
		name, version, category = "", "", ""
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[[package]]" {
			flush()
			inPackage = true
			continue
		}
		// any other table header ends the current package block
		if strings.HasPrefix(line, "[") {
			flush()
			inPackage = false
			continue
		}
		if !inPackage {
			continue
		}

		if k, v, ok := parsePoetryKeyValue(line); ok {
			switch k {
			case "name":
				name = v
			case "version":
				version = v
			case "category":
				category = v
			}
		}
	}
	flush()
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return &poetryLockfile{path: path, deps: deps}, nil
}

// parsePoetryKeyValue parses a simple `key = "value"` TOML line.
func parsePoetryKeyValue(line string) (key, value string, ok bool) {
	k, v, found := strings.Cut(line, "=")
	if !found {
		return "", "", false
	}
	key = strings.TrimSpace(k)
	value = strings.Trim(strings.TrimSpace(v), `"`)
	if value == "" {
		return "", "", false
	}
	return key, value, true
}
