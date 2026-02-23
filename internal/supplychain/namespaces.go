package supplychain

import (
	"strings"
)

// atRiskNamespaces contains npm scopes that have had compromised packages.
// Packages from these namespaces trigger warnings even if the installed
// version appears safe.
var atRiskNamespaces = []string{
	// Shai-Hulud campaign (September-November 2025)
	"@ctrl",
	"@nativescript-community",
	"@crowdstrike",
	"@asyncapi",
	"@posthog",
	"@postman",
	"@ensdomains",
	"@zapier",
	"@art-ws",
	"@ngx",
	// s1ngularity campaign (August 2025) — credential harvesting via Nx build system
	"@nx",
	"@nrwl",
}

// isAtRiskNamespace checks if a package name belongs to an at-risk namespace.
func isAtRiskNamespace(packageName string) bool {
	if !strings.HasPrefix(packageName, "@") {
		return false
	}

	// Extract the scope (e.g., "@ctrl" from "@ctrl/tinycolor")
	slashIdx := strings.Index(packageName, "/")
	if slashIdx == -1 {
		return false
	}

	scope := packageName[:slashIdx]
	for _, ns := range atRiskNamespaces {
		if scope == ns {
			return true
		}
	}

	return false
}

// getNamespaceWarning returns a warning message for an at-risk namespace.
func getNamespaceWarning(packageName string) string {
	return "Namespace '" + packageName + "' had compromised packages in a supply chain attack. This version appears safe but verify."
}
