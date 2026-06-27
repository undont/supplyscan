package supplychain

import (
	"testing"

	"github.com/undont/supplyscan/internal/types"
)

func advisoriesByType(advisories []types.SupplyChainAdvisory) map[string][]types.SupplyChainAdvisory {
	out := make(map[string][]types.SupplyChainAdvisory)
	for _, a := range advisories {
		out[a.Type] = append(out[a.Type], a)
	}
	return out
}

func TestHeuristics_InstallScript(t *testing.T) {
	deps := []types.Dependency{
		{Name: "esbuild", Version: "0.19.0", HasInstallScript: true},
		{Name: "lodash", Version: "4.17.21"},
	}

	got := advisoriesByType(Heuristics(deps))
	if len(got[advisoryInstallScript]) != 1 {
		t.Fatalf("install_script advisories = %d, want 1 (%v)", len(got[advisoryInstallScript]), got)
	}
	a := got[advisoryInstallScript][0]
	if a.Package != "esbuild" || a.Ecosystem != types.EcosystemNPM {
		t.Errorf("got %+v, want esbuild/npm", a)
	}
}

func TestHeuristics_SuspiciousUnicodeInName(t *testing.T) {
	// "express" but with a Cyrillic e (U+0435) in place of the ASCII "e"
	deps := []types.Dependency{
		{Name: "\u0435xpress", Version: "1.0.0"},
		{Name: "express", Version: "4.18.2"},
	}

	got := advisoriesByType(Heuristics(deps))
	if len(got[advisorySuspiciousUnicode]) != 1 {
		t.Fatalf("suspicious_unicode advisories = %d, want 1 (%v)", len(got[advisorySuspiciousUnicode]), got)
	}
	a := got[advisorySuspiciousUnicode][0]
	if a.Detail == "" {
		t.Error("expected a Detail describing the offending codepoint")
	}
}

func TestHeuristics_ZeroWidthInResolvedURL(t *testing.T) {
	deps := []types.Dependency{
		{Name: "pkg", Version: "1.0.0", Resolved: "https://registry.npmjs.org/pkg/-/pkg\u200b-1.0.0.tgz"},
	}

	advisories := Heuristics(deps)
	if len(advisories) != 1 {
		t.Fatalf("advisories = %d, want 1 (%v)", len(advisories), advisories)
	}
	if advisories[0].Type != advisorySuspiciousUnicode {
		t.Errorf("type = %q, want suspicious_unicode", advisories[0].Type)
	}
}

func TestHeuristics_CleanDepsProduceNothing(t *testing.T) {
	deps := []types.Dependency{
		{Name: "lodash", Version: "4.17.21", Resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"},
		{Name: "requests", Version: "2.31.0", Ecosystem: types.EcosystemPyPI},
	}

	if got := Heuristics(deps); len(got) != 0 {
		t.Errorf("expected no advisories for clean deps, got %v", got)
	}
}

func TestHeuristics_NameAndInstallScriptBothFlag(t *testing.T) {
	deps := []types.Dependency{
		{Name: "\u0435vil", Version: "1.0.0", HasInstallScript: true},
	}

	got := advisoriesByType(Heuristics(deps))
	if len(got[advisorySuspiciousUnicode]) != 1 || len(got[advisoryInstallScript]) != 1 {
		t.Errorf("expected one of each advisory, got %v", got)
	}
}
