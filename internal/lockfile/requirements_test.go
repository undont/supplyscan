package lockfile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/undont/supplyscan/internal/types"
)

func TestDetectAndParse_Requirements(t *testing.T) {
	content := `# project requirements
Flask==2.0.1
requests==2.28.1  # pinned http client
litellm==1.82.7 ; python_version >= "3.8"
PyTorch_Lightning==1.9.0
some-pkg[extra]==3.1.0
hashed==1.2.3 --hash=sha256:abcd
-r other.txt
-e .
unpinned>=1.0.0
ranged~=2.0
git+https://example.com/pkg.git
`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "requirements.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	lf, err := DetectAndParse(path)
	if err != nil {
		t.Fatalf("DetectAndParse() error = %v", err)
	}
	if lf.Type() != "requirements" {
		t.Errorf("Type() = %q, want requirements", lf.Type())
	}

	got := make(map[string]string)
	for _, dep := range lf.Dependencies() {
		if dep.Ecosystem != types.EcosystemPyPI {
			t.Errorf("dep %q ecosystem = %q, want pypi", dep.Name, dep.Ecosystem)
		}
		got[dep.Name] = dep.Version
	}

	want := map[string]string{
		"flask":             "2.0.1", // lowercased
		"requests":          "2.28.1",
		"litellm":           "1.82.7", // env marker stripped
		"pytorch-lightning": "1.9.0",  // PEP 503 normalised
		"some-pkg":          "3.1.0",  // extras stripped
		"hashed":            "1.2.3",  // inline hash stripped
	}
	for name, version := range want {
		if got[name] != version {
			t.Errorf("dep %q = %q, want %q (all deps: %v)", name, got[name], version, got)
		}
	}

	// unpinned / ranged / vcs lines must not be treated as pins
	for _, name := range []string{"unpinned", "ranged", "git+https"} {
		if _, ok := got[name]; ok {
			t.Errorf("non-pinned entry %q should be skipped, got %v", name, got)
		}
	}
}
