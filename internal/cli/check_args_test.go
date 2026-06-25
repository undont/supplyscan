package cli

import (
	"testing"

	"github.com/undont/supplyscan/internal/types"
)

func TestParseCheckArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantPkg string
		wantVer string
		wantEco string
		wantOk  bool
	}{
		{"npm default", []string{"lodash", "4.17.21"}, "lodash", "4.17.21", types.EcosystemNPM, true},
		{"explicit pypi", []string{"litellm", "1.82.7", "--ecosystem", "pypi"}, "litellm", "1.82.7", types.EcosystemPyPI, true},
		{"ecosystem equals form", []string{"litellm", "1.82.7", "--ecosystem=pypi"}, "litellm", "1.82.7", types.EcosystemPyPI, true},
		{"python alias", []string{"--ecosystem", "python", "requests", "2.0.0"}, "requests", "2.0.0", types.EcosystemPyPI, true},
		{"short flag before positionals", []string{"-e", "pypi", "flask", "2.0.1"}, "flask", "2.0.1", types.EcosystemPyPI, true},
		{"unknown ecosystem falls back to npm", []string{"x", "1.0.0", "--ecosystem", "rubygems"}, "x", "1.0.0", types.EcosystemNPM, true},
		{"missing version", []string{"lodash"}, "", "", "", false},
		{"dangling ecosystem flag", []string{"lodash", "1.0.0", "--ecosystem"}, "", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg, ver, eco, ok := parseCheckArgs(tt.args)
			if ok != tt.wantOk {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOk)
			}
			if !ok {
				return
			}
			if pkg != tt.wantPkg || ver != tt.wantVer || eco != tt.wantEco {
				t.Errorf("got (%q, %q, %q), want (%q, %q, %q)", pkg, ver, eco, tt.wantPkg, tt.wantVer, tt.wantEco)
			}
		})
	}
}
