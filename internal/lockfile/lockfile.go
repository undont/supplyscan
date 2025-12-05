// Package lockfile provides parsers for various JavaScript lockfile formats.
package lockfile

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/seanhalberthal/supplyscan-mcp/internal/types"
)

// ErrUnknownFormat indicates an unrecognised lockfile format.
var ErrUnknownFormat = errors.New("unknown lockfile format")

// Lockfile represents a parsed lockfile.
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
		return ParseNPM(path)
	case "yarn.lock":
		return ParseYarn(path)
	case "pnpm-lock.yaml":
		return ParsePNPM(path)
	case "bun.lock":
		return ParseBun(path)
	case "deno.lock":
		return ParseDeno(path)
	default:
		return nil, ErrUnknownFormat
	}
}

// FindLockfiles searches a directory for lockfiles.
// If recursive is true, it searches subdirectories as well.
func FindLockfiles(dir string, recursive bool) ([]string, error) {
	var lockfiles []string
	lockfileNames := map[string]bool{
		"package-lock.json":   true,
		"npm-shrinkwrap.json": true,
		"yarn.lock":           true,
		"pnpm-lock.yaml":      true,
		"bun.lock":            true,
		"deno.lock":           true,
	}

	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip inaccessible paths
		}

		// Skip node_modules and hidden directories
		if info.IsDir() {
			name := info.Name()
			if name == "node_modules" || (len(name) > 0 && name[0] == '.') {
				return filepath.SkipDir
			}
			// If not recursive and not the root dir, skip subdirectories
			if !recursive && path != dir {
				return filepath.SkipDir
			}
			return nil
		}

		if lockfileNames[info.Name()] {
			lockfiles = append(lockfiles, path)
		}
		return nil
	}

	if err := filepath.Walk(dir, walkFn); err != nil {
		return nil, err
	}

	return lockfiles, nil
}

// IsLockfile checks if a filename is a recognised lockfile.
func IsLockfile(filename string) bool {
	switch filename {
	case "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
		"pnpm-lock.yaml", "bun.lock", "deno.lock":
		return true
	default:
		return false
	}
}
