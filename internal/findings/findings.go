// Package findings provides utilities for detecting security findings in scan results.
package findings

import "github.com/seanhalberthal/supplyscan/internal/types"

// HasScanFindings checks if a scan result contains any vulnerabilities or supply chain compromises.
func HasScanFindings(result *types.ScanResult) bool {
	if result == nil {
		return false
	}
	return len(result.SupplyChain.Findings) > 0 || len(result.Vulnerabilities.Findings) > 0
}

// HasCheckFindings checks if a check result contains any vulnerabilities or supply chain compromises.
func HasCheckFindings(result *types.CheckResult) bool {
	if result == nil {
		return false
	}
	return result.SupplyChain.Compromised || len(result.Vulnerabilities) > 0
}
