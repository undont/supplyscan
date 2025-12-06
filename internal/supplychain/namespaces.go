package supplychain

import (
	"strings"
)

// atRiskNamespaces contains npm scopes that have had compromised packages.
// Packages from these namespaces trigger warnings even if the installed
// version appears safe.
var atRiskNamespaces = []string{
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
	return "Namespace '" + packageName + "' had compromised packages in Shai-Hulud campaign. This version appears safe but verify."
}
