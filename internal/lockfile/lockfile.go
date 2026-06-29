// Package lockfile provides parsers for various JavaScript and Python lockfile formats.
package lockfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/undont/supplyscan/internal/types"
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

// lockfile format identifiers returned by Lockfile.Type().
const (
	typeNPM         = "npm"
	typeYarnClassic = "yarn-classic"
	typeYarnBerry   = "yarn-berry"
	typePnpm        = "pnpm"
	typeBun         = "bun"
	typeDeno        = "deno"
)

// lockEcosystem groups lockfiles by the manifest ecosystem they lock.
type lockEcosystem int

const (
	ecoJS lockEcosystem = iota
	ecoPy
)

// lockfileKind is the parser and ecosystem for a recognised lockfile name.
type lockfileKind struct {
	parse     func(string) (Lockfile, error)
	ecosystem lockEcosystem
}

// lockfileRegistry is the single source of truth for recognised lockfiles;
// detection, discovery and coverage analysis all derive from it.
var lockfileRegistry = map[string]lockfileKind{
	"package-lock.json":   {parseNPM, ecoJS},
	"npm-shrinkwrap.json": {parseNPM, ecoJS},
	"yarn.lock":           {parseYarn, ecoJS},
	"pnpm-lock.yaml":      {parsePNPM, ecoJS},
	"bun.lock":            {parseBun, ecoJS},
	"deno.lock":           {parseDeno, ecoJS},
	"requirements.txt":    {parseRequirements, ecoPy},
	"poetry.lock":         {parsePoetry, ecoPy},
	"Pipfile.lock":        {parsePipfile, ecoPy},
	"uv.lock":             {parseUv, ecoPy},
	"pdm.lock":            {parsePdm, ecoPy},
}

// DetectAndParse detects the lockfile format and parses it.
func DetectAndParse(path string) (Lockfile, error) {
	kind, ok := lockfileRegistry[filepath.Base(path)]
	if !ok {
		return nil, errUnknownFormat
	}
	return kind.parse(path)
}

// skipDirNames are directories never descended into during a recursive walk.
// node_modules holds installed trees (covered by the lockfile itself); the rest
// commonly hold intentionally-vulnerable fixtures or example projects that would
// otherwise produce noise findings.
var skipDirNames = map[string]struct{}{
	"node_modules": {},
	"testdata":     {},
	"fixtures":     {},
	"__fixtures__": {},
	"__tests__":    {},
	"examples":     {},
	"example":      {},
}

// shouldSkipDir determines if a directory should be skipped during the walk.
func shouldSkipDir(name, path, rootDir string, recursive bool) bool {
	if path == rootDir { // never skip the target directory itself
		return false
	}
	if _, skip := skipDirNames[name]; skip {
		return true
	}
	if name != "" && name[0] == '.' { // hidden dirs (.git, .cache, ...)
		return true
	}
	if !recursive {
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

	walkFn := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Skip inaccessible paths within the directory
		}

		if d.IsDir() {
			if shouldSkipDir(d.Name(), path, dir, recursive) {
				return filepath.SkipDir
			}
			return nil
		}

		if isLockfile(d.Name()) {
			lockfiles = append(lockfiles, path)
		}
		return nil
	}

	if err := filepath.WalkDir(dir, walkFn); err != nil {
		return nil, err
	}

	return lockfiles, nil
}

// isLockfile checks if a filename is a recognised lockfile.
func isLockfile(filename string) bool {
	_, ok := lockfileRegistry[filename]
	return ok
}

// CoverageReporter is implemented by parsers that can report dependency sources
// they saw but could not turn into auditable pinned dependencies.
type CoverageReporter interface {
	CoverageGaps() []types.CoverageGap
}

var (
	jsManifestNames = map[string]struct{}{"package.json": {}}
	pyManifestNames = map[string]struct{}{
		"pyproject.toml": {}, "setup.py": {}, "setup.cfg": {}, "Pipfile": {},
	}
)

type dirState struct {
	jsLock, pyLock         string // lockfile path for the ecosystem, "" if none
	jsManifest, pyManifest string
	pnpmWorkspace          string // pnpm-workspace.yaml path, if present
	denoConfig             string // deno.json(c) path, if present
}

// FindUnlockedManifests classifies dependency manifests that have no co-located
// lockfile for their ecosystem. A manifest that is a member of a workspace whose
// root lockfile we scanned is reported as workspace-covered (its deps were audited
// via that root); the rest are coverage gaps that cannot be audited. It honours
// the same skip rules as FindLockfiles.
func FindUnlockedManifests(dir string, recursive bool) (gaps []types.CoverageGap, covered []types.WorkspaceCoverage, err error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, nil, err
	}
	if !info.IsDir() {
		return nil, nil, errors.New("path is not a directory")
	}

	dirs := make(map[string]*dirState)
	state := func(d string) *dirState {
		s := dirs[d]
		if s == nil {
			s = &dirState{}
			dirs[d] = s
		}
		return s
	}

	walkFn := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if shouldSkipDir(d.Name(), path, dir, recursive) {
				return filepath.SkipDir
			}
			return nil
		}
		name, parent := d.Name(), filepath.Dir(path)
		switch kind, ok := lockfileRegistry[name]; {
		case ok && kind.ecosystem == ecoJS:
			state(parent).jsLock = path
		case ok && kind.ecosystem == ecoPy:
			state(parent).pyLock = path
		case mapHas(jsManifestNames, name):
			state(parent).jsManifest = path
		case mapHas(pyManifestNames, name):
			state(parent).pyManifest = path
		case name == pnpmWorkspaceFile:
			state(parent).pnpmWorkspace = path
		case name == denoConfigFile || name == denoConfigFileC:
			state(parent).denoConfig = path
		}
		return nil
	}
	if err := filepath.WalkDir(dir, walkFn); err != nil {
		return nil, nil, err
	}

	gaps, covered = unlockedManifestGaps(filepath.Clean(dir), dirs)
	sort.Slice(gaps, func(i, j int) bool { return gaps[i].Path < gaps[j].Path })                  // deterministic
	sort.Slice(covered, func(i, j int) bool { return covered[i].Manifest < covered[j].Manifest }) // deterministic
	return gaps, covered, nil
}

const kindManifestWithoutLockfile = "manifest_without_lockfile"

// unlockedManifestGaps splits manifests with no co-located lockfile into those
// covered by a workspace root and those that are genuine coverage gaps.
func unlockedManifestGaps(root string, dirs map[string]*dirState) (gaps []types.CoverageGap, covered []types.WorkspaceCoverage) {
	jsCache, pyCache := map[string][]string{}, map[string][]string{}
	jsGlobs := func(a string) []string { return cachedGlobs(jsCache, a, dirs[a].jsWorkspaceGlobs) }
	pyGlobs := func(a string) []string { return cachedGlobs(pyCache, a, dirs[a].pyWorkspaceGlobs) }

	for d, s := range dirs {
		if s.jsManifest != "" && s.jsLock == "" {
			if lock, ok := coveringLock(root, dirs, d, jsLockOf, jsGlobs); ok {
				covered = append(covered, types.WorkspaceCoverage{Manifest: s.jsManifest, Lockfile: lock})
			} else {
				gaps = append(gaps, types.CoverageGap{
					Path: s.jsManifest, Kind: kindManifestWithoutLockfile,
					Detail: "package.json present but no JS lockfile; dependencies not audited",
				})
			}
		}
		if s.pyManifest != "" && s.pyLock == "" {
			if lock, ok := coveringLock(root, dirs, d, pyLockOf, pyGlobs); ok {
				covered = append(covered, types.WorkspaceCoverage{Manifest: s.pyManifest, Lockfile: lock})
			} else {
				gaps = append(gaps, types.CoverageGap{
					Path: s.pyManifest, Kind: kindManifestWithoutLockfile,
					Detail: "Python manifest present but no lockfile; dependencies not audited",
				})
			}
		}
	}
	return gaps, covered
}

func jsLockOf(s *dirState) string { return s.jsLock }
func pyLockOf(s *dirState) string { return s.pyLock }

func cachedGlobs(cache map[string][]string, dir string, compute func() []string) []string {
	if g, ok := cache[dir]; ok {
		return g
	}
	g := compute()
	cache[dir] = g
	return g
}

// coveringLock walks dir's ancestors (within root) for a workspace root: a dir
// with a lockfile for the ecosystem whose member globs match dir. It returns that
// root's lockfile path when found.
func coveringLock(root string, dirs map[string]*dirState, dir string,
	lockOf func(*dirState) string, globsOf func(string) []string,
) (lock string, ok bool) {
	a := dir
	for {
		a = filepath.Dir(a)
		if !withinRoot(root, a) {
			break
		}
		if s := dirs[a]; s != nil {
			if l := lockOf(s); l != "" {
				if rel, err := filepath.Rel(a, dir); err == nil && globsMatch(globsOf(a), filepath.ToSlash(rel)) {
					return l, true
				}
			}
		}
		if a == root {
			break
		}
	}
	return "", false
}

// withinRoot reports whether p is root or a descendant of it.
func withinRoot(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func mapHas(m map[string]struct{}, k string) bool { _, ok := m[k]; return ok }
