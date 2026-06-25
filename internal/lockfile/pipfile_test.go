package lockfile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/undont/supplyscan/internal/types"
)

func TestDetectAndParse_Pipfile(t *testing.T) {
	content := `{
		"_meta": {"hash": {"sha256": "abc"}},
		"default": {
			"flask": {"version": "==2.0.1"},
			"PyTorch-Lightning": {"version": "==1.9.0"},
			"somegit": {"git": "https://example.com/x.git", "ref": "abc"},
			"unpinned": {"version": ">=1.0.0"}
		},
		"develop": {
			"pytest": {"version": "==7.4.0"}
		}
	}`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "Pipfile.lock")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	lf, err := DetectAndParse(path)
	if err != nil {
		t.Fatalf("DetectAndParse() error = %v", err)
	}
	if lf.Type() != "pipfile" {
		t.Errorf("Type() = %q, want pipfile", lf.Type())
	}

	byName := make(map[string]types.Dependency)
	for _, dep := range lf.Dependencies() {
		if dep.Ecosystem != types.EcosystemPyPI {
			t.Errorf("dep %q ecosystem = %q, want pypi", dep.Name, dep.Ecosystem)
		}
		byName[dep.Name] = dep
	}

	if byName["flask"].Version != "2.0.1" {
		t.Errorf("flask = %q, want 2.0.1 (== stripped)", byName["flask"].Version)
	}
	if _, ok := byName["pytorch-lightning"]; !ok {
		t.Errorf("missing PEP 503 normalised 'pytorch-lightning', got %v", byName)
	}
	if !byName["pytest"].Dev {
		t.Error("pytest should be flagged Dev (from develop)")
	}
	if byName["flask"].Dev {
		t.Error("flask should not be flagged Dev (from default)")
	}
	// VCS entry (no version) and unpinned range must be skipped
	for _, name := range []string{"somegit", "unpinned"} {
		if _, ok := byName[name]; ok {
			t.Errorf("non-pinned entry %q should be skipped, got %v", name, byName)
		}
	}
}
