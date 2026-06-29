package semverutil

import "testing"

func TestSatisfies(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		constraint  string
		wantMatched bool
		wantOK      bool
	}{
		{"less-than matches below", "1.0.0", "< 1.2.3", true, true},
		{"less-than excludes boundary", "1.2.3", "< 1.2.3", false, true},
		{"compound AND inside", "1.5.0", ">= 1.0.0, < 2.0.0", true, true},
		{"compound AND outside", "2.5.0", ">= 1.0.0, < 2.0.0", false, true},
		{"no-space operator", "0.9.0", ">=1.0.0", false, true},
		{"unparsable constraint", "1.0.0", ">=abc", false, false},
		{"unparsable version", "latest", "< 1.2.3", false, false},
		{"empty constraint", "1.0.0", "", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, ok := Satisfies(tt.version, tt.constraint)
			if matched != tt.wantMatched || ok != tt.wantOK {
				t.Errorf("Satisfies(%q, %q) = (%v, %v), want (%v, %v)",
					tt.version, tt.constraint, matched, ok, tt.wantMatched, tt.wantOK)
			}
		})
	}
}
