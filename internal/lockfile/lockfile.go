// Package lockfile provides parsers for various JavaScript lockfile formats.
package lockfile

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/seanhalberthal/supplyscan-mcp/internal/types"
)

// errUnknownFormat indicates an unrecognised Lockfile format.
var errUnknownFormat = errors.New("unknown lockfile format")

// Lockfile represents a parsed Lockfile.
type Lockfile interface {
	// Type returns the lockfile format identifier.
	Type() string
	// Path returns the file path of the lockfile.
	Path() string
	// Dependencies returns all dependencies from the lockfile.
	Dependencies() []types.Dependency
}

// DetectAndParse detects the lockfile format and parses it.
func DetectAndParse(path string) (Lockfile, error) {
	name := filepath.Base(path)

	switch name {
	case "package-lock.json", "npm-shrinkwrap.json":
		return parseNPM(path)
	case "yarn.lock":
		return parseYarn(path)
	case "pnpm-lock.yaml":
		return parsePNPM(path)
	case "bun.lock":
		return parseBun(path)
	case "deno.lock":
		return parseDeno(path)
	default:
		return nil, errUnknownFormat
	}
}

// shouldSkipDir determines if a directory should be skipped during the walk.
func shouldSkipDir(name, path, rootDir string, recursive bool) bool {
	if name == "node_modules" {
		return true
	}
	if name != "" && name[0] == '.' {
		return true
	}
	if !recursive && path != rootDir {
		return true
	}
	return false
}

// FindLockfiles searches a directory for lockfiles.
// If recursive is true, it searches subdirectories as well.
func FindLockfiles(dir string, recursive bool) ([]string, error) {
	// Validate the directory exists first
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("path is not a directory")
	}

	var lockfiles []string

	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip inaccessible paths within the directory
		}

		if info.IsDir() {
			if shouldSkipDir(info.Name(), path, dir, recursive) {
				return filepath.SkipDir
			}
			return nil
		}

		if isLockfile(info.Name()) {
			lockfiles = append(lockfiles, path)
		}
		return nil
	}

	if err := filepath.Walk(dir, walkFn); err != nil {
		return nil, err
	}

	return lockfiles, nil
}

// isLockfile checks if a filename is a recognised lockfile.
func isLockfile(filename string) bool {
	switch filename {
	case "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
		"pnpm-lock.yaml", "bun.lock", "deno.lock":
		return true
	default:
		return false
	}
}
