// Package scanner orchestrates the security scanning process.
package scanner

import (
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/undont/supplyscan/internal/audit"
	"github.com/undont/supplyscan/internal/lockfile"
	"github.com/undont/supplyscan/internal/supplychain"
	"github.com/undont/supplyscan/internal/types"
)

// maxLockfileConcurrency bounds the parallel per-lockfile audits. The work is
// network-bound (npm + OSV round-trips), not CPU-bound, so this is a fixed,
// modest cap to stay polite to the upstream rate limits rather than NumCPU.
const maxLockfileConcurrency = 8

// lockfileResult is one lockfile's contribution to a scan, produced off the
// main goroutine so the per-lockfile work can run concurrently and be merged
// back in deterministic path order.
type lockfileResult struct {
	info       types.LockfileInfo
	findings   []types.SupplyChainFinding
	warnings   []types.SupplyChainWarning
	advisories []types.SupplyChainAdvisory
	vulns      []types.VulnerabilityFinding
	coverage   []types.CoverageGap
	auditErrs  []string
	timing     types.LockfileTiming
	depCount   int
	ok         bool   // false when the lockfile was discovered but unreadable
	skipReason string // populated when ok is false
}

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

	// Discover lockfiles and the workspace-aware coverage classification in a
	// single tree walk.
	findStart := time.Now()
	lockfilePaths, manifestGaps, workspaceCovered, err := lockfile.Discover(opts.Path, opts.Recursive)
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

	// Scan lockfiles concurrently (network-bound), then merge in path order so
	// output stays deterministic regardless of completion order.
	results := make([]lockfileResult, len(lockfilePaths))
	g := new(errgroup.Group)
	g.SetLimit(maxLockfileConcurrency)
	for i := range lockfilePaths {
		path := lockfilePaths[i]
		g.Go(func() error {
			results[i] = s.scanLockfile(path, opts.IncludeDev)
			return nil // best-effort: a single lockfile never aborts the others
		})
	}
	_ = g.Wait() // never returns an error; all goroutines return nil

	for i := range results {
		r := &results[i]
		if !r.ok {
			result.Summary.LockfilesSkipped++
			result.Skipped = append(result.Skipped, types.SkippedLockfile{
				Path:   r.timing.Path,
				Reason: r.skipReason,
			})
			continue
		}
		result.Lockfiles = append(result.Lockfiles, r.info)
		result.Summary.LockfilesScanned++
		result.Summary.TotalDependencies += r.depCount
		result.SupplyChain.Findings = append(result.SupplyChain.Findings, r.findings...)
		result.SupplyChain.Warnings = append(result.SupplyChain.Warnings, r.warnings...)
		result.SupplyChain.Advisories = append(result.SupplyChain.Advisories, r.advisories...)
		result.Vulnerabilities.Findings = append(result.Vulnerabilities.Findings, r.vulns...)
		result.Coverage = append(result.Coverage, r.coverage...)
		result.AuditErrors = append(result.AuditErrors, r.auditErrs...)
		timing.Lockfiles = append(timing.Lockfiles, r.timing)
	}

	// Manifest gaps are a whole-tree concern, independent of the per-lockfile fan-out.
	// Workspace members covered by a root lockfile are reported separately, not as gaps.
	result.Coverage = append(result.Coverage, manifestGaps...)
	result.WorkspaceCoverage = append(result.WorkspaceCoverage, workspaceCovered...)
	result.Summary.CoverageGaps = len(result.Coverage)

	// Update issue counts
	result.Summary.Issues = countIssues(result)

	timing.TotalMs = time.Since(scanStart).Milliseconds()
	result.Timing = timing

	return result, nil
}

// scanLockfile parses, supply-chain checks and audits a single lockfile. It is
// safe to call concurrently: it touches only the read-only detector/audit
// clients and returns its result rather than mutating shared scan state.
func (s *defaultScanner) scanLockfile(path string, includeDev bool) lockfileResult {
	res := lockfileResult{timing: types.LockfileTiming{Path: path}}
	lfStart := time.Now()

	parseStart := time.Now()
	lf, err := lockfile.DetectAndParse(path)
	res.timing.ParseMs = time.Since(parseStart).Milliseconds()
	if err != nil {
		res.skipReason = "unreadable or unrecognised format"
		return res // ok stays false
	}

	deps := lf.Dependencies()
	if !includeDev {
		deps = filterNonDev(deps)
	}

	res.info = types.LockfileInfo{Path: path, Type: lf.Type(), Dependencies: len(deps)}
	res.depCount = len(deps)

	if reporter, ok := lf.(lockfile.CoverageReporter); ok {
		res.coverage = reporter.CoverageGaps()
	}

	scStart := time.Now()
	findings, warnings := s.detector.CheckDependencies(deps)
	advisories := supplychain.Heuristics(deps)
	res.timing.SupplyChainMs = time.Since(scStart).Milliseconds()
	for i := range findings {
		findings[i].Lockfile = path
	}
	for i := range advisories {
		advisories[i].Lockfile = path
	}
	res.findings = findings
	res.warnings = warnings
	res.advisories = advisories

	auditStart := time.Now()
	vulns, auditErrs := s.auditVulnerabilities(deps)
	res.timing.AuditMs = time.Since(auditStart).Milliseconds()
	for i := range vulns {
		vulns[i].Lockfile = path
	}
	res.vulns = vulns
	for _, e := range auditErrs {
		res.auditErrs = append(res.auditErrs, path+": "+e)
	}

	res.timing.TotalMs = time.Since(lfStart).Milliseconds()
	res.ok = true
	return res
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
	// ecosystems use OSV.dev. A backend failure is surfaced rather than dropped.
	auditStart := time.Now()
	vulns, err := s.auditSinglePackage(ecosystem, name, version)
	timing.AuditMs = time.Since(auditStart).Milliseconds()
	if err != nil {
		result.AuditError = err.Error()
	} else if vulns != nil {
		result.Vulnerabilities = vulns
	}

	timing.TotalMs = time.Since(start).Milliseconds()
	result.Timing = timing

	return result, nil
}

// auditSinglePackage routes a single-package vuln audit to the right backend,
// returning the backend error so an unreachable API is not mistaken for a clean
// package.
func (s *defaultScanner) auditSinglePackage(ecosystem, name, version string) ([]types.VulnerabilityInfo, error) {
	if isNpm(ecosystem) {
		return s.auditClient.AuditSinglePackage(name, version)
	}
	return s.osvAudit.AuditSinglePackage(ecosystem, name, version)
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
// routing npm through the npm bulk advisory API and the rest through OSV.dev. A
// backend failure is returned as an error string rather than silently dropped,
// so the caller can distinguish "nothing found" from "could not check".
func (s *defaultScanner) auditVulnerabilities(deps []types.Dependency) (findings []types.VulnerabilityFinding, errs []string) {
	npm, other := splitByEcosystem(deps)

	if len(npm) > 0 {
		if vulns, err := s.auditClient.AuditDependencies(npm); err != nil {
			errs = append(errs, "npm audit failed: "+err.Error())
		} else {
			findings = append(findings, vulns...)
		}
	}
	if len(other) > 0 {
		if vulns, err := s.osvAudit.AuditDependencies(other); err != nil {
			errs = append(errs, "OSV audit failed: "+err.Error())
		} else {
			findings = append(findings, vulns...)
		}
	}
	return findings, errs
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
		case types.SeverityCritical:
			counts.Critical++
		case types.SeverityHigh:
			counts.High++
		case types.SeverityModerate:
			counts.Moderate++
		}
	}

	return counts
}
