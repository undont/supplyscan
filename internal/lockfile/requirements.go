package lockfile

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/undont/supplyscan/internal/types"
)

// requirementsLockfile represents a parsed pip requirements.txt file.
type requirementsLockfile struct {
	path string
	deps []types.Dependency
	gaps []types.CoverageGap
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

func (l *requirementsLockfile) CoverageGaps() []types.CoverageGap { return l.gaps }

// parseRequirements parses a requirements.txt file. Only exact pins (name==version)
// are extracted: unpinned ranges can't be matched against pinned IOCs, and IOC
// matching is the point here.
func parseRequirements(path string) (Lockfile, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	l := &requirementsLockfile{path: path}
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		raw := scanner.Text()
		name, version := parseRequirementLine(raw)
		if name == "" || version == "" {
			if isDep, reason := unpinnedRequirement(raw); isDep {
				l.gaps = append(l.gaps, types.CoverageGap{
					Path:   path,
					Kind:   "unpinned_dependency",
					Detail: fmt.Sprintf("%s — %s", sanitiseLine(strings.TrimSpace(raw)), reason),
				})
			}
			continue
		}

		key := name + "@" + version
		if seen[key] {
			continue
		}
		seen[key] = true

		l.deps = append(l.deps, types.Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: types.EcosystemPyPI,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return l, nil
}

// sanitiseLine strips control and escape characters from a raw requirements line
// before it is embedded in user-facing output, so a crafted requirements.txt
// cannot inject ANSI escape sequences into the terminal.
func sanitiseLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' || (r >= 0x20 && r != 0x7f) {
			return r
		}
		return -1
	}, s)
}

// unpinnedRequirement reports whether a non-pinned line still names a dependency
// (so its omission is a real coverage gap), and why it couldn't be pinned.
func unpinnedRequirement(line string) (isDep bool, reason string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
		return false, "" // blank, comment, or -r/-c/option line: not an auditable dep here
	}
	if i := strings.Index(line, " #"); i != -1 {
		line = strings.TrimSpace(line[:i])
	}
	if i := strings.Index(line, ";"); i != -1 {
		line = strings.TrimSpace(line[:i])
	}
	if line == "" {
		return false, ""
	}
	switch {
	case strings.Contains(line, "=="):
		return false, "" // a clean pin would have parsed already
	case strings.HasPrefix(line, "git+"), strings.Contains(line, "://"):
		return true, "VCS/URL dependency, cannot resolve to a version"
	case strings.ContainsAny(line, "<>!~"):
		return true, "version range, not an exact pin"
	default:
		return true, "no version pin"
	}
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
