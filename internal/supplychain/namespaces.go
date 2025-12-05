package supplychain

import "strings"

// AtRiskNamespaces contains npm scopes that have had compromised packages.
// Packages from these namespaces trigger warnings even if the installed
// version appears safe.
var AtRiskNamespaces = []string{
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

// IsAtRiskNamespace checks if a package name belongs to an at-risk namespace.
func IsAtRiskNamespace(packageName string) bool {
	if !strings.HasPrefix(packageName, "@") {
		return false
	}

	// Extract the scope (e.g., "@ctrl" from "@ctrl/tinycolor")
	slashIdx := strings.Index(packageName, "/")
	if slashIdx == -1 {
		return false
	}

	scope := packageName[:slashIdx]
	for _, ns := range AtRiskNamespaces {
		if scope == ns {
			return true
		}
	}

	return false
}

// GetNamespaceWarning returns a warning message for an at-risk namespace.
func GetNamespaceWarning(packageName string) string {
	return "Namespace had compromised packages in Shai-Hulud campaign. This version appears safe but verify."
}