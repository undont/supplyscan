// Package semverutil wraps Masterminds/semver constraint evaluation so callers
// across the codebase share one implementation of "does this version satisfy
// this constraint" rather than re-deriving it.
package semverutil

import "github.com/Masterminds/semver/v3"

// Satisfies reports whether version satisfies the constraint string. ok is false
// when either the version or the constraint cannot be parsed, leaving the
// fallback to the caller: the vuln-audit path treats unparsable as a match (the
// registry already filtered the package), IOC matching treats it as no match
// (never a false positive).
func Satisfies(version, constraint string) (matched, ok bool) {
	c, err := semver.NewConstraint(constraint)
	if err != nil {
		return false, false
	}
	v, err := semver.NewVersion(version)
	if err != nil {
		return false, false
	}
	return c.Check(v), true
}
