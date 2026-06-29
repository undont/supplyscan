package lockfile

import (
	"bufio"
	"os"
	"strings"

	"github.com/undont/supplyscan/internal/types"
)

// parseTOMLPackages scans a TOML lockfile built from [[package]] array tables
// (poetry, uv and pdm all share this shape) and maps each block to a Dependency
// via build. We scan line by line rather than pull in a TOML dependency, keeping
// supplyscan's own dependency surface minimal. build receives the block's simple
// key/value pairs with the right-hand side trimmed but quotes intact, so callers
// interpret strings, arrays and inline tables as they need; returning false
// skips the package. name@version duplicates are collapsed.
func parseTOMLPackages(path string, build func(fields map[string]string) (types.Dependency, bool)) ([]types.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []types.Dependency
	seen := make(map[string]bool)

	var inPackage bool
	fields := make(map[string]string)

	flush := func() {
		if inPackage && len(fields) > 0 {
			if dep, ok := build(fields); ok {
				key := dep.Name + "@" + dep.Version
				if !seen[key] {
					seen[key] = true
					deps = append(deps, dep)
				}
			}
		}
		fields = make(map[string]string)
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case line == "[[package]]":
			flush()
			inPackage = true
		case strings.HasPrefix(line, "["):
			// any other table header ends the current package block
			flush()
			inPackage = false
		case inPackage:
			if k, v, ok := strings.Cut(line, "="); ok {
				fields[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
	}
	flush()
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return deps, nil
}

// tomlUnquote strips surrounding double quotes from a TOML scalar.
func tomlUnquote(s string) string {
	return strings.Trim(s, `"`)
}

// tomlArrayContains reports whether a single-line TOML array literal such as
// `["default", "dev"]` contains value.
func tomlArrayContains(raw, value string) bool {
	raw = strings.Trim(strings.TrimSpace(raw), "[]")
	for part := range strings.SplitSeq(raw, ",") {
		if tomlUnquote(strings.TrimSpace(part)) == value {
			return true
		}
	}
	return false
}
