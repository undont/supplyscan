package findings

import (
	"testing"

	"github.com/seanhalberthal/supplyscan/internal/types"
)

// =============================================================================
// HasScanFindings Tests
// =============================================================================

func TestHasScanFindings_NoFindings(t *testing.T) {
	result := &types.ScanResult{
		SupplyChain: types.SupplyChainResult{
			Findings: []types.SupplyChainFinding{},
		},
		Vulnerabilities: types.VulnerabilityResult{
			Findings: []types.VulnerabilityFinding{},
		},
	}

	if HasScanFindings(result) {
		t.Error("HasScanFindings should return false for result with no findings")
	}
}

func TestHasScanFindings_WithSupplyChainFindings(t *testing.T) {
	result := &types.ScanResult{
		SupplyChain: types.SupplyChainResult{
			Findings: []types.SupplyChainFinding{
				{
					Package:          "malicious-pkg",
					InstalledVersion: "1.0.0",
				},
			},
		},
		Vulnerabilities: types.VulnerabilityResult{
			Findings: []types.VulnerabilityFinding{},
		},
	}

	if !HasScanFindings(result) {
		t.Error("HasScanFindings should return true when supply chain findings exist")
	}
}

func TestHasScanFindings_WithVulnerabilities(t *testing.T) {
	result := &types.ScanResult{
		SupplyChain: types.SupplyChainResult{
			Findings: []types.SupplyChainFinding{},
		},
		Vulnerabilities: types.VulnerabilityResult{
			Findings: []types.VulnerabilityFinding{
				{
					Package:          "lodash",
					InstalledVersion: "4.17.15",
				},
			},
		},
	}

	if !HasScanFindings(result) {
		t.Error("HasScanFindings should return true when vulnerabilities exist")
	}
}

func TestHasScanFindings_WithBothFindings(t *testing.T) {
	result := &types.ScanResult{
		SupplyChain: types.SupplyChainResult{
			Findings: []types.SupplyChainFinding{
				{
					Package: "malicious-pkg",
				},
			},
		},
		Vulnerabilities: types.VulnerabilityResult{
			Findings: []types.VulnerabilityFinding{
				{
					Package: "lodash",
				},
			},
		},
	}

	if !HasScanFindings(result) {
		t.Error("HasScanFindings should return true when both findings exist")
	}
}

func TestHasScanFindings_NilResult(t *testing.T) {
	if HasScanFindings(nil) {
		t.Error("HasScanFindings should return false for nil result")
	}
}

// =============================================================================
// HasCheckFindings Tests
// =============================================================================

func TestHasCheckFindings_NoFindings(t *testing.T) {
	result := &types.CheckResult{
		SupplyChain: types.CheckSupplyChainResult{
			Compromised: false,
		},
		Vulnerabilities: []types.VulnerabilityInfo{},
	}

	if HasCheckFindings(result) {
		t.Error("HasCheckFindings should return false for result with no findings")
	}
}

func TestHasCheckFindings_WithCompromise(t *testing.T) {
	result := &types.CheckResult{
		SupplyChain: types.CheckSupplyChainResult{
			Compromised: true,
			Campaigns:   []string{"shai-hulud"},
		},
		Vulnerabilities: []types.VulnerabilityInfo{},
	}

	if !HasCheckFindings(result) {
		t.Error("HasCheckFindings should return true when supply chain compromise exists")
	}
}

func TestHasCheckFindings_WithVulnerabilities(t *testing.T) {
	result := &types.CheckResult{
		SupplyChain: types.CheckSupplyChainResult{
			Compromised: false,
		},
		Vulnerabilities: []types.VulnerabilityInfo{
			{
				ID:       "GHSA-xxxx-xxxx-xxxx",
				Title:    "Prototype Pollution",
				Severity: "high",
			},
		},
	}

	if !HasCheckFindings(result) {
		t.Error("HasCheckFindings should return true when vulnerabilities exist")
	}
}

func TestHasCheckFindings_WithBothFindings(t *testing.T) {
	result := &types.CheckResult{
		SupplyChain: types.CheckSupplyChainResult{
			Compromised: true,
			Campaigns:   []string{"shai-hulud"},
		},
		Vulnerabilities: []types.VulnerabilityInfo{
			{
				ID:    "GHSA-xxxx-xxxx-xxxx",
				Title: "Prototype Pollution",
			},
		},
	}

	if !HasCheckFindings(result) {
		t.Error("HasCheckFindings should return true when both findings exist")
	}
}

func TestHasCheckFindings_NilResult(t *testing.T) {
	if HasCheckFindings(nil) {
		t.Error("HasCheckFindings should return false for nil result")
	}
}
