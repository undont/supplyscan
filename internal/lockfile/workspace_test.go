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
	}
	for _, c := range cases {
		if got := matchGlob(c.pattern, c.path); got != c.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
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
