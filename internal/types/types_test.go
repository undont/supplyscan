package types

import (
	"strings"
	"testing"
)

func TestParseEcosystem(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "npm", false},
		{"npm", "npm", false},
		{"NPM", "npm", false},
		{"pypi", "pypi", false},
		{" python ", "pypi", false},
		{"pip", "pypi", false},
		{"pypy", "", true},
		{"rubygems", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseEcosystem(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseEcosystem(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ParseEcosystem(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestValidatePackageName(t *testing.T) {
	tests := []struct {
		ecosystem string
		name      string
		wantErr   bool
	}{
		{EcosystemPyPI, "litellm", false},
		{EcosystemPyPI, "PyTorch_Lightning", false},
		{EcosystemPyPI, "zope.interface", false},
		{EcosystemPyPI, "a", false},
		{EcosystemPyPI, "@litellm", true},
		{EcosystemPyPI, "@scope/name", true},
		{EcosystemPyPI, "-leading", true},
		{EcosystemPyPI, "trailing.", true},
		{EcosystemPyPI, "", true},
		{EcosystemNPM, "@ctrl/deluge", false},
		{EcosystemNPM, "lodash", false},
		{EcosystemNPM, "JSONStream", false},
		{EcosystemNPM, "lodash.merge", false},
		{EcosystemNPM, "@types/node", false},
		{EcosystemNPM, "@litellm", true},
		{EcosystemNPM, "@scope/", true},
		{EcosystemNPM, "lodash@4", true},
		{EcosystemNPM, "flask==3.0.0", true},
		{EcosystemNPM, "has space", true},
		{EcosystemNPM, ".hidden", true},
		{EcosystemNPM, "_private", true},
		{EcosystemNPM, "a/b", true},
		{EcosystemNPM, "", true},
		{EcosystemNPM, strings.Repeat("a", 215), true},
	}

	for _, tt := range tests {
		t.Run(tt.ecosystem+"/"+tt.name, func(t *testing.T) {
			err := ValidatePackageName(tt.ecosystem, tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePackageName(%q, %q) err = %v, wantErr %v", tt.ecosystem, tt.name, err, tt.wantErr)
			}
		})
	}
}
