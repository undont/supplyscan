package lockfile

import "testing"

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"apps/*", "apps/web", true},
		{"apps/*", "apps/web/nested", false}, // * is a single segment
		{"apps/**", "apps/web/nested", true}, // ** spans depth
		{"apps/**", "apps", true},            // trailing ** matches zero or more segments
		{"packages/*", "apps/web", false},
		{"packages/foo", "packages/foo", true}, // explicit member path
		{"packages/foo-*", "packages/foo-bar", true},
		{"**", "anything/at/all", true},

		// ** in a non-terminal position spans zero or more intermediate segments
		{"src/**/test", "src/test", true},       // zero segments
		{"src/**/test", "src/a/test", true},     // one segment
		{"src/**/test", "src/a/b/c/test", true}, // many segments
		{"src/**/test", "src/a/b/nope", false},  // terminal segment mismatch
		{"**/foo", "a/b/foo", true},             // ** at the start
		{"**/foo", "foo", true},                 // ** at the start, zero prefix
		{"a/**/b/**/c", "a/x/b/y/c", true},      // two ** segments
		{"a/**/b/**/c", "a/x/b/y/d", false},     // trailing mismatch with two **

		// char class within a single segment (path.Match semantics)
		{"packages/[ab]pp", "packages/app", true},
		{"packages/[ab]pp", "packages/cpp", false},

		// empty pattern and path
		{"", "", true},
		{"", "x", false},

		// patterns exceeding the ** cap are refused rather than evaluated
		{"**/**/**/**/**/x", "a/b/c/d/e/x", false},
	}
	for _, c := range cases {
		if got := matchGlob(c.pattern, c.path); got != c.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestGlobsMatch_EmptyAndNegationOnly(t *testing.T) {
	if globsMatch(nil, "packages/foo") {
		t.Error("empty glob list should match nothing")
	}
	if globsMatch([]string{}, "packages/foo") {
		t.Error("empty glob slice should match nothing")
	}
	// a negation-only list has no positive glob, so nothing is a member
	if globsMatch([]string{"!packages/x"}, "packages/x") {
		t.Error("negation-only list should not match the negated path")
	}
	if globsMatch([]string{"!packages/x"}, "packages/y") {
		t.Error("negation-only list should not match any path")
	}
	// a "./"-prefixed positive glob is normalised before matching
	if !globsMatch([]string{"./packages/*"}, "packages/foo") {
		t.Error("./-prefixed glob should match after normalisation")
	}
}

func TestGlobsMatch_Negation(t *testing.T) {
	globs := []string{"packages/*", "!packages/excluded"}
	if !globsMatch(globs, "packages/keep") {
		t.Error("packages/keep should match")
	}
	if globsMatch(globs, "packages/excluded") {
		t.Error("packages/excluded should be negated out")
	}
	if globsMatch(globs, "apps/web") {
		t.Error("apps/web should not match a packages-only glob set")
	}
}
