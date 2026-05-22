package supplychain

import (
	"strings"
)

// namespaceCampaign describes a past supply-chain campaign that targeted an
// npm scope. We track this so the at-risk-namespace notice can name the
// campaign explicitly rather than vaguely alluding to "a supply chain attack".
type namespaceCampaign struct {
	Name string // e.g. "Shai-Hulud"
	When string // e.g. "Sep–Nov 2025"
}

// atRiskNamespaces maps npm scopes to the campaign that put them on the list.
// Packages from these scopes get an informational note even when the installed
// version isn't on any IOC list — your version is fine; the scope's history
// just means it's worth keeping an eye on future updates from those maintainers.
var atRiskNamespaces = map[string]namespaceCampaign{
	// Shai-Hulud — worm spread through compromised maintainer tokens
	"@ctrl":                   {Name: "Shai-Hulud", When: "Sep–Nov 2025"},
	"@nativescript-community": {Name: "Shai-Hulud", When: "Sep–Nov 2025"},
	"@crowdstrike":            {Name: "Shai-Hulud", When: "Sep–Nov 2025"},
	"@asyncapi":               {Name: "Shai-Hulud", When: "Sep–Nov 2025"},
	"@posthog":                {Name: "Shai-Hulud", When: "Sep–Nov 2025"},
	"@postman":                {Name: "Shai-Hulud", When: "Sep–Nov 2025"},
	"@ensdomains":             {Name: "Shai-Hulud", When: "Sep–Nov 2025"},
	"@zapier":                 {Name: "Shai-Hulud", When: "Sep–Nov 2025"},
	"@art-ws":                 {Name: "Shai-Hulud", When: "Sep–Nov 2025"},
	"@ngx":                    {Name: "Shai-Hulud", When: "Sep–Nov 2025"},

	// s1ngularity — credential harvesting via the Nx build system
	"@nx":   {Name: "s1ngularity", When: "Aug 2025"},
	"@nrwl": {Name: "s1ngularity", When: "Aug 2025"},

	// TeamPCP / Mini Shai-Hulud — self-spreading worm targeting SAP CAP,
	// TanStack, AntV, and other npm scopes
	"@cap-js":      {Name: "TeamPCP / Mini Shai-Hulud", When: "Apr–May 2026"},
	"@tanstack":    {Name: "TeamPCP / Mini Shai-Hulud", When: "Apr–May 2026"},
	"@antv":        {Name: "TeamPCP / Mini Shai-Hulud", When: "Apr–May 2026"},
	"@lint-md":     {Name: "TeamPCP / Mini Shai-Hulud", When: "Apr–May 2026"},
	"@openclaw-cn": {Name: "TeamPCP / Mini Shai-Hulud", When: "Apr–May 2026"},
	"@starmind":    {Name: "TeamPCP / Mini Shai-Hulud", When: "Apr–May 2026"},
}

// packageScope returns the npm scope (e.g. "@ctrl") for a scoped package name,
// or the empty string if the name isn't scoped.
func packageScope(packageName string) string {
	if !strings.HasPrefix(packageName, "@") {
		return ""
	}
	scope, _, ok := strings.Cut(packageName, "/")
	if !ok {
		return ""
	}
	return scope
}

// isAtRiskNamespace reports whether a package belongs to a scope that has had
// past supply-chain compromises.
func isAtRiskNamespace(packageName string) bool {
	scope := packageScope(packageName)
	if scope == "" {
		return false
	}
	_, ok := atRiskNamespaces[scope]
	return ok
}

// lookupNamespaceCampaign returns the campaign info for a package's scope.
func lookupNamespaceCampaign(packageName string) (namespaceCampaign, bool) {
	scope := packageScope(packageName)
	if scope == "" {
		return namespaceCampaign{}, false
	}
	c, ok := atRiskNamespaces[scope]
	return c, ok
}

// getNamespaceWarning returns a short, calm note explaining why the package
// shows up in the at-risk-namespace list. The wording deliberately leads with
// "your installed version is not on any IOC list" so readers don't panic.
func getNamespaceWarning(packageName string) string {
	scope := packageScope(packageName)
	c, ok := atRiskNamespaces[scope]
	if !ok {
		// Defensive fallback — callers should only invoke this after
		// isAtRiskNamespace returns true, but keep behaviour sensible.
		return "Your installed version is not on any IOC list. " +
			"The " + scope + " scope has had past supply-chain compromises — informational only."
	}
	return "Your installed version is not on any IOC list. " +
		"The " + scope + " scope was hit by the " + c.Name + " campaign (" + c.When + ") — informational only."
}
