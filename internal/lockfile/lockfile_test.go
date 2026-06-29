package lockfile

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const (
	packageLockJSON     = "package-lock.json"
	packageLockJSONPath = "../../testdata/npm-v3/package-lock.json"
)

func TestIsLockfile(t *testing.T) {
	tests := []struct {
		filename string
		want     bool
	}{
		{"package-lock.json", true},
		{"npm-shrinkwrap.json", true},
		{"yarn.lock", true},
		{"pnpm-lock.yaml", true},
		{"bun.lock", true},
		{"deno.lock", true},
		{"requirements.txt", true},
		{"poetry.lock", true},
		{"Pipfile.lock", true},
		{"uv.lock", true},
		{"pdm.lock", true},
		{"package.json", false},
		{"yarn.lock.bak", false},
		{"requirements-dev.txt", false},
		{"random.json", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			if got := isLockfile(tt.filename); got != tt.want {
				t.Errorf("IsLockfile(%q) = %v, want %v", tt.filename, got, tt.want)
			}
		})
	}
}

func TestDetectAndParse_NPMv3(t *testing.T) {
	lf, err := DetectAndParse(packageLockJSONPath)
	if err != nil {
		t.Fatalf("DetectAndParse() error = %v", err)
	}

	if lf.Type() != "npm" {
		t.Errorf("Type() = %v, want npm", lf.Type())
	}

	deps := lf.Dependencies()
	if len(deps) == 0 {
		t.Fatal("Expected dependencies, got none")
	}

	// Check for specific dependencies
	depMap := make(map[string]string)
	for _, dep := range deps {
		depMap[dep.Name] = dep.Version
	}

	// Verify known packages exist
	expectedPackages := map[string]string{
		"lodash":      "4.17.21",
		"express":     "4.18.2",
		"jest":        "29.7.0",
		"@babel/core": "7.23.0",
		"@types/node": "20.8.0",
	}

	for name, version := range expectedPackages {
		if v, ok := depMap[name]; !ok {
			t.Errorf("Expected package %s not found", name)
		} else if v != version {
			t.Errorf("Package %s version = %v, want %v", name, v, version)
		}
	}

	// Check dev flag is set correctly
	for _, dep := range deps {
		if dep.Name == "jest" && !dep.Dev {
			t.Errorf("jest should be marked as dev dependency")
		}
		if dep.Name == "lodash" && dep.Dev {
			t.Errorf("lodash should not be marked as dev dependency")
		}
	}
}

func TestDetectAndParse_NPMv2(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "npm-v2", packageLockJSON)
	lf, err := DetectAndParse(path)
	if err != nil {
		t.Fatalf("DetectAndParse() error = %v", err)
	}

	if lf.Type() != "npm" {
		t.Errorf("Type() = %v, want npm", lf.Type())
	}

	deps := lf.Dependencies()
	if len(deps) == 0 {
		t.Fatal("Expected dependencies, got none")
	}

	// Check for axios and moment
	depMap := make(map[string]string)
	for _, dep := range deps {
		depMap[dep.Name] = dep.Version
	}

	if _, ok := depMap["axios"]; !ok {
		t.Errorf("Expected axios in dependencies")
	}
}

func TestDetectAndParse_NPMv1(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "npm-v1", packageLockJSON)
	lf, err := DetectAndParse(path)
	if err != nil {
		t.Fatalf("DetectAndParse() error = %v", err)
	}

	if lf.Type() != "npm" {
		t.Errorf("Type() = %v, want npm", lf.Type())
	}

	deps := lf.Dependencies()
	depMap := make(map[string]string)
	for _, dep := range deps {
		depMap[dep.Name] = dep.Version
	}

	// v1 format has nested dependencies - check they're flattened
	expectedPackages := []string{"lodash", "debug", "ms", "typescript"}
	for _, name := range expectedPackages {
		if _, ok := depMap[name]; !ok {
			t.Errorf("Expected package %s not found in flattened dependencies", name)
		}
	}
}

func TestDetectAndParse_YarnClassic(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "yarn-classic", "yarn.lock")
	lf, err := DetectAndParse(path)
	if err != nil {
		t.Fatalf("DetectAndParse() error = %v", err)
	}

	if lf.Type() != "yarn-classic" {
		t.Errorf("Type() = %v, want yarn-classic", lf.Type())
	}

	deps := lf.Dependencies()
	if len(deps) == 0 {
		t.Fatal("Expected dependencies, got none")
	}

	depMap := make(map[string]string)
	for _, dep := range deps {
		depMap[dep.Name] = dep.Version
	}

	// Check scoped and regular packages
	expectedPackages := map[string]string{
		"lodash":            "4.17.21",
		"express":           "4.18.2",
		"@babel/code-frame": "7.22.13",
		"@types/react":      "18.2.25",
	}

	for name, version := range expectedPackages {
		if v, ok := depMap[name]; !ok {
			t.Errorf("Expected package %s not found", name)
		} else if v != version {
			t.Errorf("Package %s version = %v, want %v", name, v, version)
		}
	}
}

func TestDetectAndParse_YarnBerry(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "yarn-berry", "yarn.lock")
	lf, err := DetectAndParse(path)
	if err != nil {
		t.Fatalf("DetectAndParse() error = %v", err)
	}

	if lf.Type() != "yarn-berry" {
		t.Errorf("Type() = %v, want yarn-berry", lf.Type())
	}

	deps := lf.Dependencies()
	if len(deps) == 0 {
		t.Fatal("Expected dependencies, got none")
	}

	depMap := make(map[string]string)
	for _, dep := range deps {
		depMap[dep.Name] = dep.Version
	}

	// Check scoped package
	if v, ok := depMap["@babel/core"]; !ok {
		t.Errorf("Expected @babel/core in dependencies")
	} else if v != "7.23.0" {
		t.Errorf("@babel/core version = %v, want 7.23.0", v)
	}

	if v, ok := depMap["lodash"]; !ok {
		t.Errorf("Expected lodash in dependencies")
	} else if v != "4.17.21" {
		t.Errorf("lodash version = %v, want 4.17.21", v)
	}
}

func TestDetectAndParse_PNPM(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "pnpm", "pnpm-lock.yaml")
	lf, err := DetectAndParse(path)
	if err != nil {
		t.Fatalf("DetectAndParse() error = %v", err)
	}

	if lf.Type() != "pnpm" {
		t.Errorf("Type() = %v, want pnpm", lf.Type())
	}

	deps := lf.Dependencies()
	if len(deps) == 0 {
		t.Fatal("Expected dependencies, got none")
	}

	depMap := make(map[string]string)
	devDeps := make(map[string]bool)
	for _, dep := range deps {
		depMap[dep.Name] = dep.Version
		devDeps[dep.Name] = dep.Dev
	}

	expectedPackages := map[string]string{
		"lodash":      "4.17.21",
		"express":     "4.18.2",
		"typescript":  "5.2.2",
		"@types/node": "20.8.0",
		"@babel/core": "7.23.0",
	}

	for name, version := range expectedPackages {
		if v, ok := depMap[name]; !ok {
			t.Errorf("Expected package %s not found", name)
		} else if v != version {
			t.Errorf("Package %s version = %v, want %v", name, v, version)
		}
	}

	// Check dev flag
	if !devDeps["typescript"] {
		t.Errorf("typescript should be marked as dev dependency")
	}
	if devDeps["lodash"] {
		t.Errorf("lodash should not be marked as dev dependency")
	}
}

func TestDetectAndParse_Bun(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "bun", "bun.lock")
	lf, err := DetectAndParse(path)
	if err != nil {
		t.Fatalf("DetectAndParse() error = %v", err)
	}

	if lf.Type() != "bun" {
		t.Errorf("Type() = %v, want bun", lf.Type())
	}

	deps := lf.Dependencies()
	if len(deps) == 0 {
		t.Fatal("Expected dependencies, got none")
	}

	depMap := make(map[string]string)
	for _, dep := range deps {
		depMap[dep.Name] = dep.Version
	}

	// Verify packages are parsed including those after comments
	if _, ok := depMap["lodash"]; !ok {
		t.Errorf("Expected lodash in dependencies")
	}
	if _, ok := depMap["express"]; !ok {
		t.Errorf("Expected express in dependencies")
	}

	// Regression: positions 1–3 of each bun.lock entry (registry, metadata,
	// integrity hash) must not be treated as additional versions. If they
	// were, we'd see a duplicate dep with a sha512-prefixed "version".
	for _, dep := range deps {
		if strings.HasPrefix(dep.Version, "sha512-") || strings.HasPrefix(dep.Version, "sha256-") {
			t.Errorf("dependency %q has an integrity hash as its version: %q", dep.Name, dep.Version)
		}
	}
	if got, want := len(deps), 4; got != want {
		t.Errorf("len(deps) = %d, want %d (one entry per package — no integrity-hash duplicates)", got, want)
	}
}

func TestParseBun_NestedDependencyKeys(t *testing.T) {
	// Bun stores the hoisted copy of a package under a flat key (e.g.
	// "postcss") and any version that could not be hoisted under a
	// "parent/child" path key (e.g. "@expo/metro-config/postcss"). The
	// package name must be derived from the resolution string (entries[0]),
	// not the key — otherwise nested entries get mangled names like
	// "@expo/metro-config/postcss", which match no real npm package and
	// silently drop out of the audit, hiding vulnerable transitive versions.
	content := `{
  "lockfileVersion": 1,
  "packages": {
    "postcss": ["postcss@8.5.10", "", {}, "sha512-aaa"],
    "@expo/metro-config/postcss": ["postcss@8.4.49", "", {}, "sha512-bbb"],
    "brace-expansion": ["brace-expansion@1.1.14", "", {}, "sha512-ccc"],
    "@expo/fingerprint/minimatch/brace-expansion": ["brace-expansion@5.0.5", "", {}, "sha512-ddd"],
    "jayson/uuid": ["uuid@8.3.2", "", {}, "sha512-eee"],
    "@coinbase/wallet-sdk/@noble/hashes": ["@noble/hashes@1.8.0", "", {}, "sha512-fff"]
  }
}`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bun.lock")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	lf, err := DetectAndParse(path)
	if err != nil {
		t.Fatalf("DetectAndParse() error = %v", err)
	}

	// A package can legitimately appear at multiple versions, so key the set
	// on name@version rather than name alone.
	got := make(map[string]bool)
	for _, dep := range lf.Dependencies() {
		got[dep.Name+"@"+dep.Version] = true
	}

	want := []string{
		"postcss@8.5.10",         // hoisted, flat key
		"postcss@8.4.49",         // nested under "@expo/metro-config/postcss"
		"brace-expansion@1.1.14", // hoisted, flat key
		"brace-expansion@5.0.5",  // nested two levels deep
		"uuid@8.3.2",             // nested under non-scoped parent "jayson/uuid"
		"@noble/hashes@1.8.0",    // nested with a scoped leaf
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing dependency %q — nested-key package name was mis-extracted; got %v", w, got)
		}
	}
}

func TestDetectAndParse_Deno(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "deno", "deno.lock")
	lf, err := DetectAndParse(path)
	if err != nil {
		t.Fatalf("DetectAndParse() error = %v", err)
	}

	if lf.Type() != "deno" {
		t.Errorf("Type() = %v, want deno", lf.Type())
	}

	deps := lf.Dependencies()
	if len(deps) == 0 {
		t.Fatal("Expected dependencies, got none")
	}

	depMap := make(map[string]string)
	for _, dep := range deps {
		depMap[dep.Name] = dep.Version
	}

	expectedPackages := map[string]string{
		"lodash":      "4.17.21",
		"chalk":       "5.3.0",
		"@types/node": "20.8.0",
	}

	for name, version := range expectedPackages {
		if v, ok := depMap[name]; !ok {
			t.Errorf("Expected package %s not found", name)
		} else if v != version {
			t.Errorf("Package %s version = %v, want %v", name, v, version)
		}
	}
}

func TestDetectAndParse_UnknownFormat(t *testing.T) {
	// Create a temp file with unknown name
	tmpDir := t.TempDir()
	unknownFile := filepath.Join(tmpDir, "unknown.lock")
	if err := os.WriteFile(unknownFile, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := DetectAndParse(unknownFile)
	if !errors.Is(err, errUnknownFormat) {
		t.Errorf("Expected ErrUnknownFormat, got %v", err)
	}
}

func TestDetectAndParse_NonexistentFile(t *testing.T) {
	_, err := DetectAndParse("/nonexistent/package-lock.json")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestFindLockfiles_NonRecursive(t *testing.T) {
	tmpDir := t.TempDir()

	// Create lockfile in root
	if err := os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create lockfile in subdirectory
	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "yarn.lock"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	lockfiles, err := FindLockfiles(tmpDir, false)
	if err != nil {
		t.Fatalf("FindLockfiles() error = %v", err)
	}

	if len(lockfiles) != 1 {
		t.Errorf("FindLockfiles() found %d files, want 1", len(lockfiles))
	}

	if len(lockfiles) > 0 && filepath.Base(lockfiles[0]) != packageLockJSON {
		t.Errorf("Expected %s, got %s", packageLockJSON, filepath.Base(lockfiles[0]))
	}
}

func TestFindLockfiles_Recursive(t *testing.T) {
	tmpDir := t.TempDir()

	// Create lockfiles in various locations
	files := []string{
		filepath.Join(tmpDir, "package-lock.json"),
		filepath.Join(tmpDir, "packages", "a", "yarn.lock"),
		filepath.Join(tmpDir, "packages", "b", "pnpm-lock.yaml"),
	}

	for _, f := range files {
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		content := []byte("{}")
		if filepath.Ext(f) == ".lock" {
			content = []byte("")
		} else if filepath.Ext(f) == ".yaml" {
			content = []byte("")
		}
		if err := os.WriteFile(f, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	lockfiles, err := FindLockfiles(tmpDir, true)
	if err != nil {
		t.Fatalf("FindLockfiles() error = %v", err)
	}

	if len(lockfiles) != 3 {
		t.Errorf("FindLockfiles() found %d files, want 3", len(lockfiles))
	}
}

func TestFindLockfiles_SkipsNodeModules(t *testing.T) {
	tmpDir := t.TempDir()

	// Create lockfile in node_modules (should be skipped)
	nodeModules := filepath.Join(tmpDir, "node_modules", "some-pkg")
	if err := os.MkdirAll(nodeModules, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nodeModules, "package-lock.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create lockfile in root (should be found)
	if err := os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	lockfiles, err := FindLockfiles(tmpDir, true)
	if err != nil {
		t.Fatalf("FindLockfiles() error = %v", err)
	}

	if len(lockfiles) != 1 {
		t.Errorf("FindLockfiles() found %d files, want 1 (node_modules should be skipped)", len(lockfiles))
	}
}

func TestFindLockfiles_SkipsHiddenDirs(t *testing.T) {
	tmpDir := t.TempDir()

	// Create lockfile in hidden directory (should be skipped)
	hiddenDir := filepath.Join(tmpDir, ".hidden")
	if err := os.MkdirAll(hiddenDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hiddenDir, "package-lock.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create lockfile in root (should be found)
	if err := os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	lockfiles, err := FindLockfiles(tmpDir, true)
	if err != nil {
		t.Fatalf("FindLockfiles() error = %v", err)
	}

	if len(lockfiles) != 1 {
		t.Errorf("FindLockfiles() found %d files, want 1 (hidden dirs should be skipped)", len(lockfiles))
	}
}

func TestFindLockfiles_DotPath(t *testing.T) {
	tmpDir := t.TempDir()

	// Create lockfile in the directory
	if err := os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Change to the temp directory and search using "."
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(originalDir)

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}

	lockfiles, err := FindLockfiles(".", false)
	if err != nil {
		t.Fatalf("FindLockfiles(\".\") error = %v", err)
	}

	if len(lockfiles) != 1 {
		t.Errorf("FindLockfiles(\".\") found %d files, want 1", len(lockfiles))
	}
}

func TestExtractPackageName_NPM(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"node_modules/lodash", "lodash"},
		{"node_modules/@babel/core", "@babel/core"},
		{"node_modules/@types/node", "@types/node"},
		{"node_modules/a/node_modules/b", "b"},
		{"node_modules/@scope/pkg/node_modules/@other/dep", "@other/dep"},
		{"invalid", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := extractPackageName(tt.path); got != tt.want {
				t.Errorf("extractPackageName(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestExtractYarnPackageName(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{"lodash@^4.17.0:", "lodash"},
		{`"lodash@^4.17.0, lodash@^4.17.21":`, "lodash"},
		{"@babel/core@^7.0.0:", "@babel/core"},
		{`"@babel/core@^7.0.0, @babel/core@^7.12.0":`, "@babel/core"},
		{`"@types/react@^18.0.0":`, "@types/react"},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			if got := extractYarnPackageName(tt.line); got != tt.want {
				t.Errorf("extractYarnPackageName(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

func TestExtractBerryPackageName(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{"lodash@npm:^4.17.0", "lodash"},
		{"@babel/core@npm:^7.0.0", "@babel/core"},
		{"lodash@npm:^4.17.0, lodash@npm:^4.17.21", "lodash"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if got := extractBerryPackageName(tt.key); got != tt.want {
				t.Errorf("extractBerryPackageName(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestParsePnpmPackageKey(t *testing.T) {
	tests := []struct {
		key             string
		explicitVersion string
		wantName        string
		wantVersion     string
	}{
		// v5 format
		{"/lodash/4.17.21", "", "lodash", "4.17.21"},
		{"/@babel/core/7.23.0", "", "@babel/core", "7.23.0"},
		// v6+ format
		{"lodash@4.17.21", "", "lodash", "4.17.21"},
		{"@babel/core@7.23.0", "", "@babel/core", "7.23.0"},
		// With explicit version
		{"lodash@4.17.21", "4.17.21", "lodash", "4.17.21"},
		// With peer deps suffix
		{"/pkg/1.0.0_peer@1.0.0", "", "pkg", "1.0.0"},
		// v6 peer-dependency suffix in "(...)" form must be stripped from the
		// version, and must not corrupt the name (the suffix contains "@").
		{"/@babel/plugin-transform-react-jsx@7.22.15(@babel/core@7.23.0)", "", "@babel/plugin-transform-react-jsx", "7.22.15"},
		{"react-dom@18.2.0(react@18.2.0)", "", "react-dom", "18.2.0"},
		{"@babel/core@7.23.0(eslint@5.5.0)", "", "@babel/core", "7.23.0"},
		// Non-scoped key with an explicit version: the "(...)" suffix in the
		// key must not drag part of the peer ref into the name.
		{"react-dom@18.2.0(react@18.2.0)", "18.2.0", "react-dom", "18.2.0"},
	}

	for _, tt := range tests {
		t.Run(tt.key+"|"+tt.explicitVersion, func(t *testing.T) {
			gotName, gotVersion := parsePnpmPackageKey(tt.key, tt.explicitVersion)
			if gotName != tt.wantName || gotVersion != tt.wantVersion {
				t.Errorf("parsePnpmPackageKey(%q, %q) = (%q, %q), want (%q, %q)",
					tt.key, tt.explicitVersion, gotName, gotVersion, tt.wantName, tt.wantVersion)
			}
		})
	}
}

func TestParsePNPM_V6PeerSuffixes(t *testing.T) {
	// pnpm v6 encodes peer-dependency context as a "(...)" suffix on the
	// packages: keys. Left unstripped, the version becomes unparseable
	// (e.g. "7.23.0(react@18.2.0)") — which dodges range filtering in the
	// audit (false positives) — and the same package under two peer contexts
	// is counted as two distinct dependencies instead of deduping.
	content := `lockfileVersion: '6.0'

packages:

  /@babel/core@7.23.0(eslint@5.5.0):
    resolution: {integrity: sha512-aaa}
    dev: false

  /@babel/core@7.23.0(eslint@8.0.0):
    resolution: {integrity: sha512-aaa}
    dev: false

  /@babel/plugin-transform-react-jsx@7.22.15(@babel/core@7.23.0):
    resolution: {integrity: sha512-bbb}
    dev: false

  /react-dom@18.2.0(react@18.2.0):
    resolution: {integrity: sha512-ccc}
    dev: false
`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "pnpm-lock.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	lf, err := DetectAndParse(path)
	if err != nil {
		t.Fatalf("DetectAndParse() error = %v", err)
	}

	deps := lf.Dependencies()

	// Every version must be a clean semver — no leftover "(...)" peer suffix.
	for _, d := range deps {
		if strings.ContainsAny(d.Version, "()") {
			t.Errorf("dependency %q has an unstripped peer suffix in its version: %q", d.Name, d.Version)
		}
	}

	versions := make(map[string][]string)
	for _, d := range deps {
		versions[d.Name] = append(versions[d.Name], d.Version)
	}

	// The two @babel/core peer variants must collapse to a single 7.23.0.
	if got := versions["@babel/core"]; len(got) != 1 || got[0] != "7.23.0" {
		t.Errorf("@babel/core versions = %v, want [7.23.0] (peer variants should dedupe)", got)
	}
	if got := versions["@babel/plugin-transform-react-jsx"]; len(got) != 1 || got[0] != "7.22.15" {
		t.Errorf("@babel/plugin-transform-react-jsx versions = %v, want [7.22.15]", got)
	}
	if got := versions["react-dom"]; len(got) != 1 || got[0] != "18.2.0" {
		t.Errorf("react-dom versions = %v, want [18.2.0]", got)
	}
}

func TestParseDenoNPMKey(t *testing.T) {
	tests := []struct {
		key         string
		wantName    string
		wantVersion string
	}{
		{"lodash@4.17.21", "lodash", "4.17.21"},
		{"@types/node@20.8.0", "@types/node", "20.8.0"},
		{"chalk@5.3.0", "chalk", "5.3.0"},
		{"pkg@1.0.0_peer", "pkg", "1.0.0"}, // with peer suffix
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			gotName, gotVersion := parseDenoNPMKey(tt.key)
			if gotName != tt.wantName || gotVersion != tt.wantVersion {
				t.Errorf("parseDenoNPMKey(%q) = (%q, %q), want (%q, %q)",
					tt.key, gotName, gotVersion, tt.wantName, tt.wantVersion)
			}
		})
	}
}

func TestDependencyDeduplication(t *testing.T) {
	// Test that parsers properly deduplicate dependencies
	// This is tested implicitly through the parsing tests, but let's be explicit

	tmpDir := t.TempDir()

	// Create a lockfile with duplicate entries (can happen in v1 format with nested deps)
	lockfileContent := `{
		"name": "test",
		"version": "1.0.0",
		"lockfileVersion": 1,
		"dependencies": {
			"debug": {
				"version": "4.3.4",
				"dependencies": {
					"ms": {"version": "2.1.2"}
				}
			},
			"express": {
				"version": "4.18.2",
				"dependencies": {
					"ms": {"version": "2.1.2"}
				}
			}
		}
	}`

	lockfilePath := filepath.Join(tmpDir, "package-lock.json")
	if err := os.WriteFile(lockfilePath, []byte(lockfileContent), 0o644); err != nil {
		t.Fatal(err)
	}

	lf, err := parseNPM(lockfilePath)
	if err != nil {
		t.Fatalf("ParseNPM() error = %v", err)
	}

	deps := lf.Dependencies()
	msCount := 0
	for _, dep := range deps {
		if dep.Name == "ms" {
			msCount++
		}
	}

	if msCount != 1 {
		t.Errorf("Expected ms to appear once (deduplicated), got %d", msCount)
	}
}

// validateLockfileDependencies checks that a lockfile's dependencies are valid
func validateLockfileDependencies(t *testing.T, lf Lockfile) {
	t.Helper()
	deps := lf.Dependencies()
	if len(deps) == 0 {
		t.Errorf("Expected at least one dependency")
	}

	for _, dep := range deps {
		if dep.Name == "" {
			t.Errorf("Dependency has empty name")
		}
		if dep.Version == "" {
			t.Errorf("Dependency %s has empty version", dep.Name)
		}
	}
}

func TestParseAllFormats_Integration(t *testing.T) {
	// Integration test to verify all formats can be parsed
	testCases := []struct {
		path     string
		wantType string
	}{
		{"testdata/npm-v3/package-lock.json", "npm"},
		{"testdata/npm-v2/package-lock.json", "npm"},
		{"testdata/npm-v1/package-lock.json", "npm"},
		{"testdata/yarn-classic/yarn.lock", "yarn-classic"},
		{"testdata/yarn-berry/yarn.lock", "yarn-berry"},
		{"testdata/pnpm/pnpm-lock.yaml", "pnpm"},
		{"testdata/bun/bun.lock", "bun"},
		{"testdata/deno/deno.lock", "deno"},
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			fullPath := filepath.Join("..", "..", tc.path)
			lf, err := DetectAndParse(fullPath)
			if err != nil {
				t.Fatalf("DetectAndParse(%s) error = %v", tc.path, err)
			}

			if lf.Type() != tc.wantType {
				t.Errorf("Type() = %v, want %v", lf.Type(), tc.wantType)
			}

			validateLockfileDependencies(t, lf)
		})
	}
}

func TestLockfileInterface(t *testing.T) {
	// Test that all lockfile types implement the interface correctly
	tmpDir := t.TempDir()

	// Create a simple package-lock.json
	lockfilePath := filepath.Join(tmpDir, "package-lock.json")
	content := `{
		"name": "test",
		"version": "1.0.0",
		"lockfileVersion": 3,
		"packages": {
			"node_modules/test-pkg": {
				"version": "1.0.0"
			}
		}
	}`
	if err := os.WriteFile(lockfilePath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	var lf Lockfile
	var err error
	lf, err = DetectAndParse(lockfilePath)
	if err != nil {
		t.Fatalf("DetectAndParse() error = %v", err)
	}

	// Test interface methods
	if lf.Type() == "" {
		t.Error("Type() returned empty string")
	}

	if lf.Path() != lockfilePath {
		t.Errorf("Path() = %v, want %v", lf.Path(), lockfilePath)
	}

	deps := lf.Dependencies()
	if deps == nil {
		t.Error("Dependencies() returned nil")
	}
}

func TestSortDependencies(t *testing.T) {
	// Verify dependencies can be sorted consistently
	path := filepath.Join("..", "..", "testdata", "npm-v3", "package-lock.json")
	lf, err := DetectAndParse(path)
	if err != nil {
		t.Fatalf("DetectAndParse() error = %v", err)
	}

	deps := lf.Dependencies()

	// Sort by name
	sort.Slice(deps, func(i, j int) bool {
		return deps[i].Name < deps[j].Name
	})

	// Verify sorting worked
	for i := 1; i < len(deps); i++ {
		if deps[i-1].Name > deps[i].Name {
			t.Errorf("Dependencies not sorted: %s > %s", deps[i-1].Name, deps[i].Name)
		}
	}
}

func TestFindLockfiles_SkipsFixtureDirs(t *testing.T) {
	tmpDir := t.TempDir()

	// Lockfiles in scope-guard dirs must NOT be discovered.
	for _, dir := range []string{"fixtures", "testdata", "examples", "example", "__fixtures__", "__tests__"} {
		sub := filepath.Join(tmpDir, dir)
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sub, "package-lock.json"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// A lockfile in a normal subdir IS discovered.
	normal := filepath.Join(tmpDir, "packages", "app")
	if err := os.MkdirAll(normal, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(normal, "package-lock.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	lockfiles, err := FindLockfiles(tmpDir, true)
	if err != nil {
		t.Fatalf("FindLockfiles() error = %v", err)
	}
	if len(lockfiles) != 1 {
		t.Errorf("FindLockfiles() found %d files, want 1 (fixture/example dirs should be skipped)", len(lockfiles))
	}
}

func TestFindLockfiles_RootExemption(t *testing.T) {
	// Scanning a directory literally named "fixtures" as the target still finds
	// its lockfile — the skip set never applies to the root itself.
	tmpDir := t.TempDir()
	root := filepath.Join(tmpDir, "fixtures")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	lockfiles, err := FindLockfiles(root, true)
	if err != nil {
		t.Fatalf("FindLockfiles() error = %v", err)
	}
	if len(lockfiles) != 1 {
		t.Errorf("FindLockfiles() found %d files, want 1 (root named 'fixtures' is exempt)", len(lockfiles))
	}
}

func TestFindUnlockedManifests(t *testing.T) {
	tmpDir := t.TempDir()

	mkdir := func(parts ...string) string {
		d := filepath.Join(append([]string{tmpDir}, parts...)...)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		return d
	}
	write := func(dir, name string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// gap: package.json with no JS lockfile
	jsGap := mkdir("js-no-lock")
	write(jsGap, "package.json")

	// no gap: package.json + package-lock.json
	jsOK := mkdir("js-locked")
	write(jsOK, "package.json")
	write(jsOK, "package-lock.json")

	// gap: pyproject.toml with no Python lockfile
	pyGap := mkdir("py-no-lock")
	write(pyGap, "pyproject.toml")

	// no gap: pyproject.toml + requirements.txt (requirements counts as a py lockfile)
	pyOK := mkdir("py-locked")
	write(pyOK, "pyproject.toml")
	write(pyOK, "requirements.txt")

	// scope guard: a manifest inside fixtures/ or node_modules/ produces no gap
	fixture := mkdir("fixtures", "vuln-app")
	write(fixture, "package.json")
	nm := mkdir("node_modules", "dep")
	write(nm, "package.json")

	gaps, _, err := FindUnlockedManifests(tmpDir, true)
	if err != nil {
		t.Fatalf("FindUnlockedManifests() error = %v", err)
	}

	if len(gaps) != 2 {
		t.Fatalf("FindUnlockedManifests() found %d gaps, want 2:\n%+v", len(gaps), gaps)
	}
	for _, g := range gaps {
		if g.Kind != "manifest_without_lockfile" {
			t.Errorf("gap kind = %q, want manifest_without_lockfile", g.Kind)
		}
	}
	// deterministic order (sorted by path)
	if !sort.SliceIsSorted(gaps, func(i, j int) bool { return gaps[i].Path < gaps[j].Path }) {
		t.Error("gaps are not sorted by path")
	}

	gotPaths := map[string]bool{}
	for _, g := range gaps {
		gotPaths[g.Path] = true
	}
	if !gotPaths[filepath.Join(jsGap, "package.json")] {
		t.Error("missing gap for js-no-lock/package.json")
	}
	if !gotPaths[filepath.Join(pyGap, "pyproject.toml")] {
		t.Error("missing gap for py-no-lock/pyproject.toml")
	}
	if gotPaths[filepath.Join(jsOK, "package.json")] {
		t.Error("js-locked should not be a gap")
	}
	if gotPaths[filepath.Join(pyOK, "pyproject.toml")] {
		t.Error("py-locked (requirements.txt present) should not be a gap")
	}
}

func TestFindUnlockedManifests_Workspaces(t *testing.T) {
	tmpDir := t.TempDir()

	writeFile := func(content string, parts ...string) string {
		p := filepath.Join(append([]string{tmpDir}, parts...)...)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// bun/npm/yarn array form: root package.json workspaces + bun.lock
	bunLock := writeFile("{}", "bun", "bun.lock")
	writeFile(`{"name":"root","workspaces":["apps/*","packages/*"]}`, "bun", "package.json")
	bunWeb := writeFile("{}", "bun", "apps", "web", "package.json")
	bunShared := writeFile("{}", "bun", "packages", "shared", "package.json")
	bunDocs := writeFile("{}", "bun", "docs", "package.json") // not a member → gap

	// yarn object form: {"workspaces": {"packages": [...]}}
	yarnLock := writeFile("", "yarn", "yarn.lock")
	writeFile(`{"name":"y","workspaces":{"packages":["mods/*"]}}`, "yarn", "package.json")
	yarnMod := writeFile("{}", "yarn", "mods", "m", "package.json")

	// pnpm: separate pnpm-workspace.yaml alongside pnpm-lock.yaml
	pnpmLock := writeFile("", "pnpm", "pnpm-lock.yaml")
	writeFile("packages:\n  - \"pkgs/*\"\n", "pnpm", "pnpm-workspace.yaml")
	pnpmPkg := writeFile("{}", "pnpm", "pkgs", "a", "package.json")

	// deno: deno.json workspace lists explicit member paths
	denoLock := writeFile("{}", "deno", "deno.lock")
	writeFile(`{"workspace":["./members/d"]}`, "deno", "deno.json")
	denoMember := writeFile("{}", "deno", "members", "d", "package.json")

	// uv: [tool.uv.workspace] members in the root pyproject.toml + uv.lock
	uvLock := writeFile("", "uv", "uv.lock")
	writeFile("[project]\nname = \"uv\"\n\n[tool.uv.workspace]\nmembers = [\"libs/*\"]\nexclude = [\"libs/skip\"]\n", "uv", "pyproject.toml")
	uvLib := writeFile("[project]\nname = \"x\"\n", "uv", "libs", "x", "pyproject.toml")
	uvSkip := writeFile("[project]\nname = \"s\"\n", "uv", "libs", "skip", "pyproject.toml") // excluded → gap
	uvOther := writeFile("[project]\nname = \"o\"\n", "uv", "other", "pyproject.toml")       // not a member → gap

	gaps, covered, err := FindUnlockedManifests(tmpDir, true)
	if err != nil {
		t.Fatalf("FindUnlockedManifests() error = %v", err)
	}

	wantCovered := map[string]string{
		bunWeb:     bunLock,
		bunShared:  bunLock,
		yarnMod:    yarnLock,
		pnpmPkg:    pnpmLock,
		denoMember: denoLock,
		uvLib:      uvLock,
	}
	gotCovered := map[string]string{}
	for _, c := range covered {
		gotCovered[c.Manifest] = c.Lockfile
	}
	if len(gotCovered) != len(wantCovered) {
		t.Fatalf("covered count = %d, want %d:\n%+v", len(gotCovered), len(wantCovered), covered)
	}
	for manifest, lock := range wantCovered {
		if gotCovered[manifest] != lock {
			t.Errorf("manifest %s covered by %q, want %q", manifest, gotCovered[manifest], lock)
		}
	}

	wantGaps := map[string]bool{bunDocs: true, uvSkip: true, uvOther: true}
	gotGaps := map[string]bool{}
	for _, g := range gaps {
		gotGaps[g.Path] = true
	}
	if len(gotGaps) != len(wantGaps) {
		t.Fatalf("gap count = %d, want %d:\n%+v", len(gotGaps), len(wantGaps), gaps)
	}
	for p := range wantGaps {
		if !gotGaps[p] {
			t.Errorf("missing gap for %s", p)
		}
	}
}
