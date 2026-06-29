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
	lockfiles, _, err := walkProject(dir, recursive)
	return lockfiles, err
}

// projectWalk accumulates the result of a single project tree walk: the
// lockfile paths to scan and the per-directory lock/manifest/workspace state
// used for coverage analysis.
type projectWalk struct {
	lockfiles []string
	dirs      map[string]*dirState
}

func (w *projectWalk) state(dir string) *dirState {
	s := w.dirs[dir]
	if s == nil {
		s = &dirState{}
		w.dirs[dir] = s
	}
	return s
}

// classifyFile records one regular file against the directory it lives in,
// sorting it into a lockfile, manifest or workspace declaration as recognised.
func (w *projectWalk) classifyFile(path, name string) {
	parent := filepath.Dir(path)
	switch kind, ok := lockfileRegistry[name]; {
	case ok && kind.ecosystem == ecoJS:
		w.lockfiles = append(w.lockfiles, path)
		w.state(parent).jsLock = path
	case ok && kind.ecosystem == ecoPy:
		w.lockfiles = append(w.lockfiles, path)
		w.state(parent).pyLock = path
	case mapHas(jsManifestNames, name):
		w.state(parent).jsManifest = path
	case mapHas(pyManifestNames, name):
		w.state(parent).pyManifest = path
	case name == pnpmWorkspaceFile:
		w.state(parent).pnpmWorkspace = path
	case name == denoConfigFile || name == denoConfigFileC:
		w.state(parent).denoConfig = path
	}
}

// walkProject walks dir once, collecting lockfile paths and the per-directory
// lock/manifest/workspace state used for coverage analysis. A single walk backs
// both FindLockfiles and the coverage analysis so a scan stats the tree once.
func walkProject(dir string, recursive bool) (lockfiles []string, dirs map[string]*dirState, err error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, nil, err
	}
	if !info.IsDir() {
		return nil, nil, errors.New("path is not a directory")
	}

	w := &projectWalk{dirs: make(map[string]*dirState)}
	walkFn := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible paths within the directory
		}
		if d.IsDir() {
			if shouldSkipDir(d.Name(), path, dir, recursive) {
				return filepath.SkipDir
			}
			return nil
		}
		w.classifyFile(path, d.Name())
		return nil
	}
	if err := filepath.WalkDir(dir, walkFn); err != nil {
		return nil, nil, err
	}
	return w.lockfiles, w.dirs, nil
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
	_, gaps, covered, err = Discover(dir, recursive)
	return gaps, covered, err
}

// Discover walks dir once and returns the lockfile paths to scan together with
// the workspace-aware coverage classification. It is the single-walk equivalent
// of FindLockfiles followed by FindUnlockedManifests, so the scanner stats the
// tree only once.
func Discover(dir string, recursive bool) (lockfiles []string, gaps []types.CoverageGap, covered []types.WorkspaceCoverage, err error) {
	lockfiles, dirs, err := walkProject(dir, recursive)
	if err != nil {
		return nil, nil, nil, err
	}
	gaps, covered = unlockedManifestGaps(filepath.Clean(dir), dirs)
	sort.Slice(gaps, func(i, j int) bool { return gaps[i].Path < gaps[j].Path })                  // deterministic
	sort.Slice(covered, func(i, j int) bool { return covered[i].Manifest < covered[j].Manifest }) // deterministic
	return lockfiles, gaps, covered, nil
}

const kindManifestWithoutLockfile = "manifest_without_lockfile"

// ecoCoverage describes how to evaluate manifest coverage for one ecosystem:
// where its lockfile, manifest and workspace globs live, and the gap message to
// emit when a manifest is left unaudited. Adding an ecosystem is one table entry.
type ecoCoverage struct {
	manifestOf func(*dirState) string
	lockOf     func(*dirState) string
	globsOf    func(*dirState) []string
	gapDetail  string
}

var ecoCoverages = []ecoCoverage{
	{
		manifestOf: func(s *dirState) string { return s.jsManifest },
		lockOf:     func(s *dirState) string { return s.jsLock },
		globsOf:    (*dirState).jsWorkspaceGlobs,
		gapDetail:  "package.json present but no JS lockfile; dependencies not audited",
	},
	{
		manifestOf: func(s *dirState) string { return s.pyManifest },
		lockOf:     func(s *dirState) string { return s.pyLock },
		globsOf:    (*dirState).pyWorkspaceGlobs,
		gapDetail:  "Python manifest present but no lockfile; dependencies not audited",
	},
}

// unlockedManifestGaps splits manifests with no co-located lockfile into those
// covered by a workspace root and those that are genuine coverage gaps.
func unlockedManifestGaps(root string, dirs map[string]*dirState) (gaps []types.CoverageGap, covered []types.WorkspaceCoverage) {
	for _, eco := range ecoCoverages {
		cache := map[string][]string{}
		globs := func(a string) []string { return cachedGlobs(cache, a, func() []string { return eco.globsOf(dirs[a]) }) }
		for d, s := range dirs {
			manifest := eco.manifestOf(s)
			if manifest == "" || eco.lockOf(s) != "" {
				continue
			}
			if lock, ok := coveringLock(root, dirs, d, eco.lockOf, globs); ok {
				covered = append(covered, types.WorkspaceCoverage{Manifest: manifest, Lockfile: lock})
			} else {
				gaps = append(gaps, types.CoverageGap{Path: manifest, Kind: kindManifestWithoutLockfile, Detail: eco.gapDetail})
			}
		}
	}
	return gaps, covered
}

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
