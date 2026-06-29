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
		{"non-semver version", "linked", "< 1.2.3", false, false},
		{"empty version", "", "< 1.2.3", false, false},
		{"empty constraint", "1.0.0", "", false, false},
		{"incomplete operator", "1.0.0", "<", false, false},
		{"single exact version", "1.0.0", "1.0.0", true, true},
		// compound OR ranges (npm vulnerable_versions style)
		{"OR first branch in", "3.0.4", "<3.1.3 || >=4.0.0 <5.1.7", true, true},
		{"OR first branch boundary", "3.1.3", "<3.1.3 || >=4.0.0 <5.1.7", false, true},
		{"OR second branch in", "5.1.6", "<3.1.3 || >=4.0.0 <5.1.7", true, true},
		{"OR second branch boundary", "5.1.7", "<3.1.3 || >=4.0.0 <5.1.7", false, true},
		{"OR above all ranges", "9.0.6", "<3.1.3 || >=4.0.0 <5.1.7", false, true},
		// caret/tilde (npm advisory ranges)
		{"caret matches within minor", "1.5.0", "^1.0.0", true, true},
		{"caret excludes next major", "2.0.0", "^1.0.0", false, true},
		{"tilde matches within patch", "1.2.9", "~1.2.0", true, true},
		{"tilde excludes next minor", "1.3.0", "~1.2.0", false, true},
		// pre-release: Masterminds does not match a pre-release against a plain
		// range without a pre-release tag (standard SemVer behaviour)
		{"pre-release not matched by plain range", "3.0.5-alpha.1", "<3.0.5", false, true},
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
