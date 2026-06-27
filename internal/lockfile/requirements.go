package lockfile

import (
	"bufio"
	"os"
	"strings"

	"github.com/undont/supplyscan/internal/types"
)

// requirementsLockfile represents a parsed pip requirements.txt file.
type requirementsLockfile struct {
	path string
	deps []types.Dependency
}

func (l *requirementsLockfile) Type() string {
	return "requirements"
}

func (l *requirementsLockfile) Path() string {
	return l.path
}

func (l *requirementsLockfile) Dependencies() []types.Dependency {
	return l.deps
}

// parseRequirements parses a requirements.txt file. Only exact pins (name==version)
// are extracted: unpinned ranges can't be matched against pinned IOCs, and IOC
// matching is the point here.
func parseRequirements(path string) (Lockfile, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []types.Dependency
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		name, version := parseRequirementLine(scanner.Text())
		if name == "" || version == "" {
			continue
		}

		key := name + "@" + version
		if seen[key] {
			continue
		}
		seen[key] = true

		deps = append(deps, types.Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: types.EcosystemPyPI,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return &requirementsLockfile{path: path, deps: deps}, nil
}

// parseRequirementLine extracts a normalised name and pinned version from a
// single requirements line, or empty strings if it isn't an exact pin.
func parseRequirementLine(line string) (name, version string) {
	line = strings.TrimSpace(line)

	// drop comments and continuation/option/url lines
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
		return "", ""
	}
	if i := strings.Index(line, " #"); i != -1 {
		line = strings.TrimSpace(line[:i])
	}

	// strip environment markers (";") and inline hashes
	if i := strings.Index(line, ";"); i != -1 {
		line = strings.TrimSpace(line[:i])
	}
	if i := strings.Index(line, "--hash"); i != -1 {
		line = strings.TrimSpace(line[:i])
	}

	// only exact pins are usable
	before, after, ok := strings.Cut(line, "==")
	if !ok {
		return "", ""
	}

	// drop extras: "package[extra]" -> "package"
	if i := strings.Index(before, "["); i != -1 {
		before = before[:i]
	}

	name = types.NormalizePyPIName(before)
	version = strings.TrimSpace(after)
	// a second "==" or trailing comparators mean it isn't a clean pin
	if name == "" || version == "" || strings.ContainsAny(version, " ,<>=!~*") {
		return "", ""
	}
	return name, version
}
