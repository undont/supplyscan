package lockfile

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/seanhalberthal/supplyscan/internal/types"
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

// Regex pattern for yarn classic format
// Matches version line:   version "4.17.21"
var yarnVersionRe = regexp.MustCompile(`^\s+version\s+"([^"]+)"`)

// shouldSkipLine checks if a line should be skipped.
func shouldSkipLine(line string) bool {
	if strings.HasPrefix(line, "#") {
		return true
	}
	if strings.TrimSpace(line) == "" {
		return true
	}
	return false
}

// isHeaderLine checks if a line is a package entry header (unindented).
func isHeaderLine(line string) bool {
	return !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t")
}

// processVersionLine extracts version info and updates dependencies if a match is found.
// Returns true if a version was processed.
func processVersionLine(line, currentPackage string, seen map[string]bool, deps *[]types.Dependency) bool {
	if currentPackage == "" {
		return false
	}

	matches := yarnVersionRe.FindStringSubmatch(line)
	if matches == nil {
		return false
	}

	version := matches[1]
	key := currentPackage + "@" + version

	if !seen[key] {
		seen[key] = true
		*deps = append(*deps, types.Dependency{
			Name:    currentPackage,
			Version: version,
		})
	}
	return true
}

// scanYarnLockfile scans a bufio.Scanner and extracts dependencies.
func scanYarnLockfile(scanner *bufio.Scanner) ([]types.Dependency, error) {
	var deps []types.Dependency
	seen := make(map[string]bool)
	var currentPackage string

	for scanner.Scan() {
		line := scanner.Text()

		if shouldSkipLine(line) {
			continue
		}

		if isHeaderLine(line) {
			currentPackage = extractYarnPackageName(line)
			continue
		}

		if processVersionLine(line, currentPackage, seen, &deps) {
			currentPackage = ""
		}
	}

	return deps, scanner.Err()
}

// parseYarnClassic parses a yarn.lock v1 (classic) file.
func parseYarnClassic(path string) (Lockfile, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf("failed to close yarn.lock file: %v\n", err)
		}
	}(file)

	scanner := bufio.NewScanner(file)
	deps, err := scanYarnLockfile(scanner)
	if err != nil {
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
// Classic format starts with "# yarn Lockfile v1"
func isYarnClassic(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf("failed to close yarn.lock file: %v\n", err)
		}
	}(file)

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
