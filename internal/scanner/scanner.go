// Package scanner orchestrates the security scanning process.
package scanner

import (
	"github.com/seanhalberthal/supplyscan-mcp/internal/audit"
	"github.com/seanhalberthal/supplyscan-mcp/internal/lockfile"
	"github.com/seanhalberthal/supplyscan-mcp/internal/supplychain"
	"github.com/seanhalberthal/supplyscan-mcp/internal/types"
)

// Scanner orchestrates the complete security scan.
type Scanner struct {
	detector    *supplychain.Detector
	auditClient *audit.Client
}

// New creates a new scanner.
func New() (*Scanner, error) {
	detector, err := supplychain.NewDetector()
	if err != nil {
		return nil, err
	}

	return &Scanner{
		detector:    detector,
		auditClient: audit.NewClient(),
	}, nil
}

// ScanOptions configures the scan behaviour.
type ScanOptions struct {
	Path       string
	Recursive  bool
	IncludeDev bool
}

// Scan performs a full security scan on a project.
func (s *Scanner) Scan(opts ScanOptions) (*types.ScanResult, error) {
	// Ensure IOC database is loaded (continue without it if unavailable)
	_ = s.detector.EnsureLoaded()

	// Find lockfiles
	lockfilePaths, err := lockfile.FindLockfiles(opts.Path, opts.Recursive)
	if err != nil {
		return nil, err
	}

	result := &types.ScanResult{
		Summary: types.ScanSummary{
			LockfilesScanned:  0,
			TotalDependencies: 0,
			Issues:            types.IssueCounts{},
		},
		SupplyChain: types.SupplyChainResult{
			Findings: []types.SupplyChainFinding{},
			Warnings: []types.SupplyChainWarning{},
		},
		Vulnerabilities: types.VulnerabilityResult{
			Findings: []types.VulnerabilityFinding{},
		},
		Lockfiles: []types.LockfileInfo{},
	}

	// Process each lockfile
	for _, path := range lockfilePaths {
		lf, err := lockfile.DetectAndParse(path)
		if err != nil {
			continue // Skip unreadable lockfiles
		}

		deps := lf.Dependencies()

		// Filter dev dependencies if needed
		if !opts.IncludeDev {
			deps = filterNonDev(deps)
		}

		// Add lockfile info
		result.Lockfiles = append(result.Lockfiles, types.LockfileInfo{
			Path:         path,
			Type:         lf.Type(),
			Dependencies: len(deps),
		})

		result.Summary.LockfilesScanned++
		result.Summary.TotalDependencies += len(deps)

		// Check supply chain
		findings, warnings := s.detector.CheckDependencies(deps)
		for i := range findings {
			findings[i].Lockfile = path
		}
		result.SupplyChain.Findings = append(result.SupplyChain.Findings, findings...)
		result.SupplyChain.Warnings = append(result.SupplyChain.Warnings, warnings...)

		// Audit for vulnerabilities
		vulns, err := s.auditClient.AuditDependencies(deps)
		if err == nil {
			for i := range vulns {
				vulns[i].Lockfile = path
			}
			result.Vulnerabilities.Findings = append(result.Vulnerabilities.Findings, vulns...)
		}
	}

	// Update issue counts
	result.Summary.Issues = countIssues(result)

	return result, nil
}

// CheckPackage checks a single package for issues.
func (s *Scanner) CheckPackage(name, version string) (*types.CheckResult, error) {
	// Ensure IOC database is loaded (continue without it if unavailable)
	_ = s.detector.EnsureLoaded()

	result := &types.CheckResult{
		SupplyChain: types.CheckSupplyChainResult{
			Compromised: false,
		},
		Vulnerabilities: []types.VulnerabilityInfo{},
	}

	// Check supply chain
	if finding := s.detector.CheckPackage(name, version); finding != nil {
		result.SupplyChain.Compromised = true
		result.SupplyChain.Campaigns = []string{finding.Type}
	}

	// Audit for vulnerabilities
	vulns, err := s.auditClient.AuditSinglePackage(name, version)
	if err == nil && vulns != nil {
		result.Vulnerabilities = vulns
	}

	return result, nil
}

// Refresh refreshes the IOC database.
func (s *Scanner) Refresh(force bool) (*types.RefreshResult, error) {
	return s.detector.Refresh(force)
}

// GetStatus returns the current scanner status.
func (s *Scanner) GetStatus() types.IOCDatabaseStatus {
	return s.detector.GetStatus()
}

// filterNonDev removes dev dependencies from the list.
func filterNonDev(deps []types.Dependency) []types.Dependency {
	filtered := make([]types.Dependency, 0)
	for _, dep := range deps {
		if !dep.Dev {
			filtered = append(filtered, dep)
		}
	}
	return filtered
}

// countIssues counts issues by severity.
func countIssues(result *types.ScanResult) types.IssueCounts {
	counts := types.IssueCounts{
		SupplyChain: len(result.SupplyChain.Findings),
	}

	for _, vuln := range result.Vulnerabilities.Findings {
		switch vuln.Severity {
		case "critical":
			counts.Critical++
		case "high":
			counts.High++
		case "moderate":
			counts.Moderate++
		}
	}

	return counts
}
