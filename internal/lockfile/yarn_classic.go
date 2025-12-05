package lockfile

import (
	"bufio"
	"os"
	"regexp"
	"strings"

	"github.com/seanhalberthal/supplyscan-mcp/internal/types"
)

// yarnClassicLockfile represents a parsed yarn.lock v1 (classic) file.
type yarnClassicLockfile struct {
	path string
	deps []types.Dependency
}

func (l *yarnClassicLockfile) Type() string {
	return "yarn-classic"
}

func (l *yarnClassicLockfile) Path() string {
	return l.path
}

func (l *yarnClassicLockfile) Dependencies() []types.Dependency {
	return l.deps
}

// Regex patterns for yarn classic format
var (
	// Matches entry headers like: lodash@^4.17.0: or "@babel/core@^7.0.0":
	yarnEntryHeaderRe = regexp.MustCompile(`^"?(@?[^@"]+)@[^:]+":?$`)
	// Matches version line:   version "4.17.21"
	yarnVersionRe = regexp.MustCompile(`^\s+version\s+"([^"]+)"`)
)

// parseYarnClassic parses a yarn.lock v1 (classic) file.
func parseYarnClassic(path string) (Lockfile, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []types.Dependency
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(file)
	var currentPackage string

	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments and empty lines
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		// Check for entry header (unindented line)
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			currentPackage = extractYarnPackageName(line)
			continue
		}

		// Check for version line (indented)
		if currentPackage != "" {
			if matches := yarnVersionRe.FindStringSubmatch(line); matches != nil {
				version := matches[1]
				key := currentPackage + "@" + version

				if !seen[key] {
					seen[key] = true
					deps = append(deps, types.Dependency{
						Name:    currentPackage,
						Version: version,
					})
				}
				currentPackage = "" // Reset for next entry
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return &yarnClassicLockfile{
		path: path,
		deps: deps,
	}, nil
}

// extractYarnPackageName extracts the package name from a yarn entry header.
// Examples:
//   - lodash@^4.17.0:
//   - "lodash@^4.17.0, lodash@^4.17.21":
//   - "@babel/core@^7.0.0":
//   - "@babel/core@^7.0.0, @babel/core@^7.12.0":
func extractYarnPackageName(line string) string {
	// Remove trailing colon and quotes
	line = strings.TrimSuffix(line, ":")
	line = strings.Trim(line, "\"")

	// Handle multiple specifiers (take the first one)
	if idx := strings.Index(line, ","); idx != -1 {
		line = line[:idx]
	}

	// Extract package name (everything before the last @)
	// For scoped packages like @babel/core@^7.0.0, we need to be careful
	if strings.HasPrefix(line, "@") {
		// Scoped package: find the second @ which separates name from version
		atIdx := strings.Index(line[1:], "@")
		if atIdx != -1 {
			return line[:atIdx+1]
		}
	} else {
		// Regular package: find the first @
		atIdx := strings.Index(line, "@")
		if atIdx != -1 {
			return line[:atIdx]
		}
	}

	return line
}

// isYarnClassic checks if a yarn.lock file is v1 (classic) format.
// Classic format starts with "# yarn lockfile v1"
func isYarnClassic(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		// First non-empty line should be a comment for classic format
		if strings.Contains(line, "yarn lockfile v1") {
			return true, nil
		}
		// If we hit a non-comment line first, check for YAML indicators
		if strings.HasPrefix(line, "__metadata:") {
			return false, nil // Berry format
		}
		break
	}

	// Default to classic if unsure (simpler format)
	return true, nil
}