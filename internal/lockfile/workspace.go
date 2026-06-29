package lockfile

import (
	"encoding/json"
	"os"
	"path"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/undont/supplyscan/internal/jsonc"
)

// workspace declaration filenames that live alongside a lockfile but are not
// lockfiles themselves. package.json (npm/yarn/bun) and pyproject.toml (uv) are
// already tracked as manifests; these two carry the membership globs separately.
const (
	pnpmWorkspaceFile = "pnpm-workspace.yaml"
	denoConfigFile    = "deno.json"
	denoConfigFileC   = "deno.jsonc"
)

// jsWorkspaceGlobs returns the workspace member globs a JS workspace root
// declares, drawn from whichever declaration files it has: package.json
// "workspaces" (npm/yarn/bun), pnpm-workspace.yaml, or deno.json "workspace".
func (s *dirState) jsWorkspaceGlobs() []string {
	var globs []string
	if s.jsManifest != "" {
		globs = append(globs, packageJSONWorkspaceGlobs(s.jsManifest)...)
	}
	if s.pnpmWorkspace != "" {
		globs = append(globs, pnpmWorkspaceGlobs(s.pnpmWorkspace)...)
	}
	if s.denoConfig != "" {
		globs = append(globs, denoWorkspaceGlobs(s.denoConfig)...)
	}
	return globs
}

// pyWorkspaceGlobs returns the workspace member globs a Python workspace root
// declares via pyproject.toml's [tool.uv.workspace] table.
func (s *dirState) pyWorkspaceGlobs() []string {
	if s.pyManifest != "" {
		return uvWorkspaceGlobs(s.pyManifest)
	}
	return nil
}

// packageJSONWorkspaceGlobs extracts the "workspaces" globs from a package.json.
// The field is either an array of globs or yarn's object form
// {"packages": [...], "nohoist": [...]}.
func packageJSONWorkspaceGlobs(manifest string) []string {
	data, err := os.ReadFile(manifest)
	if err != nil {
		return nil
	}
	var doc struct {
		Workspaces json.RawMessage `json:"workspaces"`
	}
	if json.Unmarshal(data, &doc) != nil || len(doc.Workspaces) == 0 {
		return nil
	}
	var rawArray []string
	if json.Unmarshal(doc.Workspaces, &rawArray) == nil {
		return rawArray
	}
	var obj struct {
		Packages []string `json:"packages"`
	}
	if json.Unmarshal(doc.Workspaces, &obj) == nil {
		return obj.Packages
	}
	return nil
}

// pnpmWorkspaceGlobs extracts the "packages" globs from a pnpm-workspace.yaml.
func pnpmWorkspaceGlobs(file string) []string {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil
	}
	var doc struct {
		Packages []string `yaml:"packages"`
	}
	if yaml.Unmarshal(data, &doc) != nil {
		return nil
	}
	return doc.Packages
}

// denoWorkspaceGlobs extracts the "workspace" member paths from a deno.json(c).
// Deno lists explicit member directories rather than globs; the leading "./" is
// stripped so they match like a plain path glob.
func denoWorkspaceGlobs(file string) []string {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil
	}
	data = jsonc.StripComments(data)
	var doc struct {
		Workspace []string `json:"workspace"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	out := make([]string, 0, len(doc.Workspace))
	for _, m := range doc.Workspace {
		out = append(out, strings.TrimPrefix(m, "./"))
	}
	return out
}

// uvWorkspaceGlobs extracts member globs from a pyproject.toml's
// [tool.uv.workspace] table. "members" entries are positive globs; "exclude"
// entries become negations. Parsed line by line to avoid a TOML dependency,
// matching the convention in pytoml.go; single- and multi-line arrays are both
// handled.
func uvWorkspaceGlobs(manifest string) []string {
	data, err := os.ReadFile(manifest)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	var globs []string
	inSection := false
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "[") {
			inSection = line == "[tool.uv.workspace]"
			continue
		}
		if !inSection {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key != "members" && key != "exclude" {
			continue
		}
		rawArray := strings.TrimSpace(val)
		for !strings.Contains(rawArray, "]") && i+1 < len(lines) {
			i++
			rawArray += " " + strings.TrimSpace(lines[i])
		}
		for _, item := range tomlStringArray(rawArray) {
			if key == "exclude" {
				globs = append(globs, "!"+item)
			} else {
				globs = append(globs, item)
			}
		}
	}
	return globs
}

// tomlStringArray parses a TOML inline array of quoted strings such as
// `["packages/*", "libs/*"]` into its elements.
func tomlStringArray(raw string) []string {
	raw = strings.Trim(strings.TrimSpace(raw), "[]")
	var out []string
	for part := range strings.SplitSeq(raw, ",") {
		if v := tomlUnquote(strings.TrimSpace(part)); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// globsMatch reports whether rel (a member directory relative to a workspace
// root, slash-separated) is a member under the given globs. A path is a member
// when it matches at least one positive glob and no "!"-prefixed negation.
func globsMatch(globs []string, rel string) bool {
	matched := false
	for _, g := range globs {
		g = strings.TrimPrefix(g, "./")
		if neg, ok := strings.CutPrefix(g, "!"); ok {
			if matchGlob(strings.TrimPrefix(neg, "./"), rel) {
				return false
			}
			continue
		}
		if matchGlob(g, rel) {
			matched = true
		}
	}
	return matched
}

// matchGlob matches a workspace glob against a slash-separated path. It supports
// "*" and character classes within a single segment (via path.Match) plus "**"
// spanning zero or more segments.
func matchGlob(pattern, name string) bool {
	pattern = strings.TrimSuffix(pattern, "/")
	return matchSegments(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

func matchSegments(pat, name []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			if len(pat) == 1 {
				return true // trailing ** matches any remaining depth
			}
			for i := 0; i <= len(name); i++ {
				if matchSegments(pat[1:], name[i:]) {
					return true
				}
			}
			return false
		}
		if len(name) == 0 {
			return false
		}
		if ok, err := path.Match(pat[0], name[0]); err != nil || !ok {
			return false
		}
		pat, name = pat[1:], name[1:]
	}
	return len(name) == 0
}
