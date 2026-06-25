package lockfile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/undont/supplyscan/internal/types"
)

func TestDetectAndParse_Pdm(t *testing.T) {
	content := `[metadata]
groups = ["default", "dev"]
lock_version = "4.4"

[[package]]
name = "flask"
version = "2.0.1"
requires_python = ">=3.6"
groups = ["default"]
summary = "A simple framework"

[[package]]
name = "PyTorch-Lightning"
version = "1.9.0"
groups = ["default"]

[[package]]
name = "pytest"
version = "7.4.0"
groups = ["dev"]
`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "pdm.lock")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	lf, err := DetectAndParse(path)
	if err != nil {
		t.Fatalf("DetectAndParse() error = %v", err)
	}
	if lf.Type() != "pdm" {
		t.Errorf("Type() = %q, want pdm", lf.Type())
	}

	deps := lf.Dependencies()
	byName := make(map[string]types.Dependency)
	for _, dep := range deps {
		if dep.Ecosystem != types.EcosystemPyPI {
			t.Errorf("dep %q ecosystem = %q, want pypi", dep.Name, dep.Ecosystem)
		}
		byName[dep.Name] = dep
	}

	// the [metadata] groups array must not be mistaken for a package
	if len(deps) != 3 {
		t.Errorf("len(deps) = %d, want 3 (%v)", len(deps), byName)
	}
	if byName["flask"].Version != "2.0.1" {
		t.Errorf("flask = %q, want 2.0.1", byName["flask"].Version)
	}
	if _, ok := byName["pytorch-lightning"]; !ok {
		t.Errorf("missing PEP 503 normalised 'pytorch-lightning', got %v", byName)
	}
	if !byName["pytest"].Dev {
		t.Error("pytest should be flagged Dev (groups = dev)")
	}
	if byName["flask"].Dev {
		t.Error("flask should not be flagged Dev (groups = default)")
	}
}
