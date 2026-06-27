package supplychain

import (
	"fmt"
	"unicode"

	"github.com/undont/supplyscan/internal/types"
)

// advisory type identifiers.
const (
	advisoryInstallScript     = "install_script"
	advisorySuspiciousUnicode = "suspicious_unicode"
)

// Heuristics applies low-noise, advisory-only checks that complement IOC
// matching. These don't assert a package is malicious, they surface traits worth
// a human glance: a lifecycle/install script (the Shai-Hulud propagation vector)
// and non-ASCII or invisible characters in a name or resolved URL (used to hide
// payloads from review, as in GlassWorm). They never affect exit status.
func Heuristics(deps []types.Dependency) []types.SupplyChainAdvisory {
	var advisories []types.SupplyChainAdvisory

	for i := range deps {
		dep := &deps[i]

		if a := suspiciousUnicodeAdvisory(dep); a != nil {
			advisories = append(advisories, *a)
		}

		if dep.HasInstallScript {
			advisories = append(advisories, types.SupplyChainAdvisory{
				Type:             advisoryInstallScript,
				Package:          dep.Name,
				InstalledVersion: dep.Version,
				Ecosystem:        normalizeEcosystem(dep.Ecosystem),
				Note:             "runs a lifecycle/install script; review if unexpected",
			})
		}
	}

	return advisories
}

// suspiciousUnicodeAdvisory flags a dependency whose name or resolved URL carries
// a non-ASCII or invisible/control rune. The name is checked first since a
// poisoned name is the stronger signal.
func suspiciousUnicodeAdvisory(dep *types.Dependency) *types.SupplyChainAdvisory {
	if r, ok := firstSuspiciousRune(dep.Name); ok {
		return &types.SupplyChainAdvisory{
			Type:             advisorySuspiciousUnicode,
			Package:          dep.Name,
			InstalledVersion: dep.Version,
			Ecosystem:        normalizeEcosystem(dep.Ecosystem),
			Detail:           fmt.Sprintf("name contains %s", describeRune(r)),
			Note:             "non-ASCII or invisible characters in a package name are a common obfuscation trick",
		}
	}
	if r, ok := firstSuspiciousRune(dep.Resolved); ok {
		return &types.SupplyChainAdvisory{
			Type:             advisorySuspiciousUnicode,
			Package:          dep.Name,
			InstalledVersion: dep.Version,
			Ecosystem:        normalizeEcosystem(dep.Ecosystem),
			Detail:           fmt.Sprintf("resolved URL contains %s", describeRune(r)),
			Note:             "non-ASCII or invisible characters in a resolved URL are a common obfuscation trick",
		}
	}
	return nil
}

// firstSuspiciousRune returns the first rune that is outside printable ASCII:
// any rune above U+007F, or an ASCII control character. Package names and
// registry URLs are ASCII in practice, so anything else warrants a look.
func firstSuspiciousRune(s string) (rune, bool) {
	for _, r := range s {
		if r > unicode.MaxASCII || r < 0x20 {
			return r, true
		}
	}
	return 0, false
}

// invisibleRuneNames labels the well-known invisible codepoints that show up in
// these attacks; anything else is reported by codepoint alone.
var invisibleRuneNames = map[rune]string{
	0x200B: "zero-width space",
	0x200C: "zero-width non-joiner",
	0x200D: "zero-width joiner",
	0x2060: "word joiner",
	0xFEFF: "zero-width no-break space",
}

// describeRune renders a rune as its codepoint, naming the well-known invisible
// ones.
func describeRune(r rune) string {
	if name, ok := invisibleRuneNames[r]; ok {
		return fmt.Sprintf("U+%04X (%s)", r, name)
	}
	return fmt.Sprintf("U+%04X", r)
}
