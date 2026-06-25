// Package scanner orchestrates the security scanning process.
package scanner

import (
	"time"

	"github.com/undont/supplyscan/internal/audit"
	"github.com/undont/supplyscan/internal/lockfile"
	"github.com/undont/supplyscan/internal/supplychain"
	"github.com/undont/supplyscan/internal/types"
)

// Scanner defines the interface for security scanning operations.
type Scanner interface {
	Scan(ScanOptions) (*types.ScanResult, error)
	CheckPackage(ecosystem, name, version string) (*types.CheckResult, error)
	Refresh(force bool) (*types.RefreshResult, error)
	GetStatus() types.IOCDatabaseStatus
}

// defaultScanner orchestrates the complete security scan.
type defaultScanner struct {
	detector    *supplychain.Detector
	auditClient *audit.Client
	osvAudit    *audit.OSVClient
}

// New creates a new scanner.
func New() (Scanner, error) {
	detector, err := supplychain.NewDetector()
	if err != nil {
		return nil, err
	}

	return &defaultScanner{
		detector:    detector,
		auditClient: audit.NewClient(),
		osvAudit:    audit.NewOSVClient(),
	}, nil
}

// ScanOptions configures the scan behaviour.
type ScanOptions struct {
	Path       string
	Recursive  bool
	IncludeDev bool
}

// Scan performs a full security scan on a project.
func (s *defaultScanner) Scan(opts ScanOptions) (*types.ScanResult, error) {
	scanStart := time.Now()
	timing := &types.ScanTiming{}

	// Ensure IOC database is loaded (continue without it if unavailable)
	iocStart := time.Now()
	_ = s.detector.EnsureLoaded()
	timing.IOCLoadMs = time.Since(iocStart).Milliseconds()

	// Find lockfiles
	findStart := time.Now()
	lockfilePaths, err := lockfile.FindLockfiles(opts.Path, opts.Recursive)
	timing.FindLockfilesMs = time.Since(findStart).Milliseconds()
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
			Findings:   []types.SupplyChainFinding{},
			Warnings:   []types.SupplyChainWarning{},
			Advisories: []types.SupplyChainAdvisory{},
		},
		Vulnerabilities: types.VulnerabilityResult{
			Findings: []types.VulnerabilityFinding{},
		},
		Lockfiles: []types.LockfileInfo{},
	}

	// Process each lockfile
	for _, path := range lockfilePaths {
		lfStart := time.Now()
		lfTiming := types.LockfileTiming{Path: path}

		// Parse lockfile
		parseStart := time.Now()
		lf, err := lockfile.DetectAndParse(path)
		lfTiming.ParseMs = time.Since(parseStart).Milliseconds()
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
		scStart := time.Now()
		findings, warnings := s.detector.CheckDependencies(deps)
		advisories := supplychain.Heuristics(deps)
		lfTiming.SupplyChainMs = time.Since(scStart).Milliseconds()
		for i := range findings {
			findings[i].Lockfile = path
		}
		for i := range advisories {
			advisories[i].Lockfile = path
		}
		result.SupplyChain.Findings = append(result.SupplyChain.Findings, findings...)
		result.SupplyChain.Warnings = append(result.SupplyChain.Warnings, warnings...)
		result.SupplyChain.Advisories = append(result.SupplyChain.Advisories, advisories...)

		// Audit for vulnerabilities. npm deps go through the npm bulk advisory
		// API; everything else (PyPI today) goes through OSV.dev, which spans
		// multiple ecosystems. Both are best-effort: errors leave the findings
		// untouched and supply-chain IOC matching above still covers the deps.
		auditStart := time.Now()
		vulns := s.auditVulnerabilities(deps)
		lfTiming.AuditMs = time.Since(auditStart).Milliseconds()
		for i := range vulns {
			vulns[i].Lockfile = path
		}
		result.Vulnerabilities.Findings = append(result.Vulnerabilities.Findings, vulns...)

		lfTiming.TotalMs = time.Since(lfStart).Milliseconds()
		timing.Lockfiles = append(timing.Lockfiles, lfTiming)
	}

	// Update issue counts
	result.Summary.Issues = countIssues(result)

	timing.TotalMs = time.Since(scanStart).Milliseconds()
	result.Timing = timing

	return result, nil
}

// CheckPackage checks a single package for issues. ecosystem is "npm" (default
// when empty) or "pypi".
func (s *defaultScanner) CheckPackage(ecosystem, name, version string) (*types.CheckResult, error) {
	start := time.Now()
	timing := &types.CheckTiming{}

	// Ensure IOC database is loaded (continue without it if unavailable)
	iocStart := time.Now()
	_ = s.detector.EnsureLoaded()
	timing.IOCLoadMs = time.Since(iocStart).Milliseconds()

	result := &types.CheckResult{
		SupplyChain: types.CheckSupplyChainResult{
			Compromised: false,
		},
		Vulnerabilities: []types.VulnerabilityInfo{},
	}

	// Check supply chain.
	scStart := time.Now()
	if finding := s.detector.CheckPackage(ecosystem, name, version); finding != nil {
		result.SupplyChain.Compromised = true
		result.SupplyChain.Campaigns = []string{finding.Type}
	}
	timing.SupplyChainMs = time.Since(scStart).Milliseconds()

	// Audit for vulnerabilities. npm uses the npm bulk advisory API; other
	// ecosystems use OSV.dev.
	auditStart := time.Now()
	vulns := s.auditSinglePackage(ecosystem, name, version)
	timing.AuditMs = time.Since(auditStart).Milliseconds()
	if vulns != nil {
		result.Vulnerabilities = vulns
	}

	timing.TotalMs = time.Since(start).Milliseconds()
	result.Timing = timing

	return result, nil
}

// auditSinglePackage routes a single-package vuln audit to the right backend.
func (s *defaultScanner) auditSinglePackage(ecosystem, name, version string) []types.VulnerabilityInfo {
	if isNpm(ecosystem) {
		vulns, err := s.auditClient.AuditSinglePackage(name, version)
		if err != nil {
			return nil
		}
		return vulns
	}
	vulns, err := s.osvAudit.AuditSinglePackage(ecosystem, name, version)
	if err != nil {
		return nil
	}
	return vulns
}

// Refresh refreshes the IOC database.
func (s *defaultScanner) Refresh(force bool) (*types.RefreshResult, error) {
	return s.detector.Refresh(force)
}

// GetStatus returns the current scanner status.
func (s *defaultScanner) GetStatus() types.IOCDatabaseStatus {
	return s.detector.GetStatus()
}

// auditVulnerabilities audits a dependency set, splitting it by ecosystem and
// routing npm through the npm bulk advisory API and the rest through OSV.dev.
func (s *defaultScanner) auditVulnerabilities(deps []types.Dependency) []types.VulnerabilityFinding {
	npm, other := splitByEcosystem(deps)

	var findings []types.VulnerabilityFinding
	if vulns, err := s.auditClient.AuditDependencies(npm); err == nil {
		findings = append(findings, vulns...)
	}
	if vulns, err := s.osvAudit.AuditDependencies(other); err == nil {
		findings = append(findings, vulns...)
	}
	return findings
}

// splitByEcosystem partitions deps into npm (empty ecosystem counts as npm) and
// everything else.
func splitByEcosystem(deps []types.Dependency) (npm, other []types.Dependency) {
	for _, dep := range deps {
		if isNpm(dep.Ecosystem) {
			npm = append(npm, dep)
		} else {
			other = append(other, dep)
		}
	}
	return npm, other
}

// isNpm reports whether an ecosystem id refers to npm (empty defaults to npm).
func isNpm(ecosystem string) bool {
	return ecosystem == "" || ecosystem == types.EcosystemNPM
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
