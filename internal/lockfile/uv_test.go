package lockfile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/undont/supplyscan/internal/types"
)

func TestDetectAndParse_Uv(t *testing.T) {
	content := `version = 1
requires-python = ">=3.9"

[[package]]
name = "my-project"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "flask"
version = "2.0.1"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "click" },
    { name = "jinja2" },
]

[[package]]
name = "PyTorch-Lightning"
version = "1.9.0"
source = { registry = "https://pypi.org/simple" }
`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "uv.lock")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	lf, err := DetectAndParse(path)
	if err != nil {
		t.Fatalf("DetectAndParse() error = %v", err)
	}
	if lf.Type() != "uv" {
		t.Errorf("Type() = %q, want uv", lf.Type())
	}

	deps := lf.Dependencies()
	byName := make(map[string]types.Dependency)
	for _, dep := range deps {
		if dep.Ecosystem != types.EcosystemPyPI {
			t.Errorf("dep %q ecosystem = %q, want pypi", dep.Name, dep.Ecosystem)
		}
		byName[dep.Name] = dep
	}

	// the editable workspace root must be skipped; the multi-line dependencies
	// array of flask must not bleed extra entries in
	if len(deps) != 2 {
		t.Errorf("len(deps) = %d, want 2 (%v)", len(deps), byName)
	}
	if byName["flask"].Version != "2.0.1" {
		t.Errorf("flask = %q, want 2.0.1", byName["flask"].Version)
	}
	if _, ok := byName["pytorch-lightning"]; !ok {
		t.Errorf("missing PEP 503 normalised 'pytorch-lightning', got %v", byName)
	}
	if _, ok := byName["my-project"]; ok {
		t.Errorf("editable workspace root should be skipped, got %v", byName)
	}
}
