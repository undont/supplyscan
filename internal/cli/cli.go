// Package cli provides the command-line interface for supplyscan.
package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/charmbracelet/huh/spinner"

	"github.com/undont/supplyscan/internal/findings"
	"github.com/undont/supplyscan/internal/scanner"
	"github.com/undont/supplyscan/internal/types"
)

// exitFunc is the function used to exit the program. Override in tests.
var exitFunc = os.Exit

// outputJSON controls whether to output raw JSON instead of styled output.
var outputJSON bool

// Run executes the CLI with the given scanner and arguments.
func Run(scan scanner.Scanner, args []string) {
	// Parse global flags
	args = parseGlobalFlags(args)

	if len(args) == 0 {
		printUsage()
		return
	}

	switch args[0] {
	case "status":
		runStatus(scan)
	case ".":
		dispatchScan(scan, args)
	case "scan":
		dispatchScan(scan, args)
	case "check":
		pkg, version, ecosystem, ok := parseCheckArgs(args[1:])
		if !ok {
			printStyledError("check requires package and version arguments")
			exitFunc(1)
			return
		}
		runCheck(scan, ecosystem, pkg, version)
	case "refresh":
		force := len(args) > 1 && args[1] == "--force"
		runRefresh(scan, force)
	case "help", "--help", "-h":
		printUsage()
	default:
		printStyledError("Unknown command: %s", args[0])
		printUsage()
		exitFunc(1)
		return
	}
}

// dispatchScan is extracted so both "supplyscan scan ." and "supplyscan ." can yield the same result
func dispatchScan(scan scanner.Scanner, args []string) {
	path := "."
	flagArgs := args[1:]
	if len(args) >= 2 && !strings.HasPrefix(args[1], "-") {
		path = args[1]
		flagArgs = args[2:]
	}
	runScan(scan, path, parseScanFlags(flagArgs))
}

// parseGlobalFlags extracts global flags from args and returns remaining args.
func parseGlobalFlags(args []string) []string {
	var remaining []string
	for _, arg := range args {
		switch arg {
		case "--json":
			outputJSON = true
		default:
			remaining = append(remaining, arg)
		}
	}
	return remaining
}

func printUsage() {
	fmt.Println(headerStyle.Render("supplyscan") + " - JavaScript and Python supply-chain scanner")
	fmt.Println()
	fmt.Println(formatSection("Usage"))
	fmt.Println("  supplyscan <command> [options]    Run CLI commands (default)")
	fmt.Println("  supplyscan --mcp                  Run as MCP server")
	fmt.Println()
	fmt.Println(formatSection("Commands"))
	fmt.Println("  status                            Show scanner version and database info")
	fmt.Println("  scan [path] [--recursive]         Scan a project for vulnerabilities (default: .)")
	fmt.Println("  check <package> <version>         Check a single package@version")
	fmt.Println("    [--ecosystem npm|pypi]          Registry to check against (default: npm)")
	fmt.Println("  refresh [--force]                 Update IOC database from upstream")
	fmt.Println()
	fmt.Println(formatSection("Flags"))
	fmt.Println("  --json                            Output raw JSON (for scripting)")
}

type scanOptions struct {
	Recursive  bool
	IncludeDev bool
	JSON       bool
}

// parseCheckArgs extracts the package, version and ecosystem from check args.
// The ecosystem comes from "--ecosystem <value>" / "--ecosystem=<value>" (or the
// "-e" short form) and defaults to npm; the two positional args are package and
// version.
func parseCheckArgs(args []string) (pkg, version, ecosystem string, ok bool) {
	ecosystem = types.EcosystemNPM
	var positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--ecosystem" || arg == "-e":
			if i+1 >= len(args) {
				return "", "", "", false
			}
			i++
			ecosystem = normalizeCheckEcosystem(args[i])
		case strings.HasPrefix(arg, "--ecosystem="):
			ecosystem = normalizeCheckEcosystem(strings.TrimPrefix(arg, "--ecosystem="))
		default:
			positional = append(positional, arg)
		}
	}

	if len(positional) < 2 {
		return "", "", "", false
	}
	return positional[0], positional[1], ecosystem, true
}

// normalizeCheckEcosystem maps user-facing ecosystem aliases onto internal ids.
func normalizeCheckEcosystem(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "pypi", "python", "pip":
		return types.EcosystemPyPI
	default:
		return types.EcosystemNPM
	}
}

func parseScanFlags(args []string) scanOptions {
	opts := scanOptions{IncludeDev: true}
	for _, arg := range args {
		switch arg {
		case "--recursive", "-r":
			opts.Recursive = true
		case "--no-dev":
			opts.IncludeDev = false
		}
	}
	return opts
}

func runStatus(scan scanner.Scanner) {
	status := types.StatusResponse{
		Version:            types.Version,
		IOCDatabase:        scan.GetStatus(),
		SupportedLockfiles: types.SupportedLockfiles,
	}

	if outputJSON {
		printJSON(status)
		return
	}

	// Styled output
	fmt.Println(formatHeader("Scanner Status"))
	fmt.Println(formatDivider(40))
	fmt.Println()
	fmt.Printf("%s %s\n", formatLabel("Version"), status.Version)
	fmt.Println()

	fmt.Println(formatSection("IOC Database"))
	printIOCSourceDetails(status.IOCDatabase)
	fmt.Println()

	fmt.Println(formatSection("Supported Lockfiles"))
	for _, lf := range status.SupportedLockfiles {
		fmt.Printf("  %s %s\n", formatMuted(bullet), lf)
	}
}

func printIOCSourceDetails(db types.IOCDatabaseStatus) {
	if len(db.SourceDetails) == 0 {
		fmt.Printf("  %s\n", formatMuted("Not loaded - run 'refresh' to fetch"))
		return
	}

	for _, source := range db.Sources {
		info, ok := db.SourceDetails[source]
		if !ok {
			continue
		}
		printIOCSourceLine(source, info)
	}
}

func printIOCSourceLine(source string, info types.SourceStatusInfo) {
	if info.Success {
		fetchedAgo := formatTimeAgo(info.LastFetched)
		fmt.Printf("  %s %s %s, %s\n",
			formatMuted(bullet),
			source,
			formatMuted(fmt.Sprintf("(%d packages)", info.PackageCount)),
			formatMuted(fetchedAgo))
		return
	}
	fmt.Printf("  %s %s %s\n",
		formatMuted(bullet),
		source,
		formatWarning("(failed to fetch)"))
}

func runScan(scan scanner.Scanner, path string, opts scanOptions) {
	var result *types.ScanResult
	var err error

	if outputJSON {
		// No spinner for JSON output
		result, err = scan.Scan(scanner.ScanOptions{
			Path:       path,
			Recursive:  opts.Recursive,
			IncludeDev: opts.IncludeDev,
		})
	} else {
		// Show spinner during scan
		_ = spinner.New().
			Title(fmt.Sprintf("Scanning %s...", path)).
			Action(func() {
				result, err = scan.Scan(
					scanner.ScanOptions{
						Path:       path,
						Recursive:  opts.Recursive,
						IncludeDev: opts.IncludeDev,
					},
				)
			}).
			Style(spinnerStyle).
			Run()
	}

	if err != nil {
		printStyledError("%v", err)
		exitFunc(1)
		return
	}

	if outputJSON {
		printJSON(result)
	} else {
		// Styled output
		printScanResult(result)
	}

	// Exit with code 2 if vulnerabilities or supply chain issues found
	if findings.HasScanFindings(result) {
		exitFunc(2)
	}
}

func printScanResult(result *types.ScanResult) {
	fmt.Println(formatHeader("Scan Results"))
	fmt.Println(formatDivider(50))
	fmt.Println()

	printScanSummary(result)
	printIssuesSummary(&result.Summary.Issues)
	printSupplyChainFindings(result.SupplyChain.Findings)
	printSupplyChainWarnings(result.SupplyChain.Warnings)
	printSupplyChainAdvisories(result.SupplyChain.Advisories)
	printVulnerabilities(result.Vulnerabilities.Findings)
	printLockfiles(result.Lockfiles)
	printScanTiming(result.Timing)
}

func printScanSummary(result *types.ScanResult) {
	fmt.Println(formatSection("Summary"))
	fmt.Printf("  %s %d\n", formatLabel("Lockfiles scanned"), result.Summary.LockfilesScanned)
	fmt.Printf("  %s %d\n", formatLabel("Dependencies"), result.Summary.TotalDependencies)
	fmt.Println()
}

func printIssuesSummary(issues *types.IssueCounts) {
	issueCount := issues.Critical + issues.High + issues.Moderate + issues.SupplyChain
	if issueCount == 0 {
		fmt.Println(formatSuccess("No issues found"))
		fmt.Println()
		return
	}

	fmt.Println(formatSection("Issues Found"))
	if issues.Critical > 0 {
		fmt.Printf("  %s %d\n", formatSeverity("critical"), issues.Critical)
	}
	if issues.High > 0 {
		fmt.Printf("  %s %d\n", formatSeverity("high"), issues.High)
	}
	if issues.Moderate > 0 {
		fmt.Printf("  %s %d\n", formatSeverity("moderate"), issues.Moderate)
	}
	if issues.SupplyChain > 0 {
		fmt.Printf("  %s %d\n", formatLabel("supply chain"), issues.SupplyChain)
	}
	fmt.Println()
}

func printSupplyChainFindings(scFindings []types.SupplyChainFinding) {
	if len(scFindings) == 0 {
		return
	}

	fmt.Println(formatSection("Supply Chain Compromises"))
	for i := range scFindings {
		f := &scFindings[i]
		fmt.Printf("  %s %s\n", crossStyle.Render(crossMark), formatPackageVersion(f.Package, f.InstalledVersion))
		fmt.Printf("    %s %s\n", formatLabel("Severity"), formatSeverity(f.Severity))
		fmt.Printf("    %s %s\n", formatLabel("Type"), f.Type)
		if f.Action != "" {
			fmt.Printf("    %s %s\n", formatLabel("Action"), f.Action)
		}
		if len(f.Campaigns) > 0 {
			fmt.Printf("    %s %s\n", formatLabel("Campaigns"), strings.Join(f.Campaigns, ", "))
		}
		fmt.Println()
	}
}

func printSupplyChainWarnings(warnings []types.SupplyChainWarning) {
	if len(warnings) == 0 {
		return
	}

	// Group by namespace so 8 entries for @tanstack don't read like 8
	// independent problems. These are informational notes, not findings —
	// the wording and styling reflect that.
	type group struct {
		scope        string
		campaign     string
		campaignWhen string
		packages     []string
	}
	order := []string{}
	groups := map[string]*group{}
	for i := range warnings {
		w := &warnings[i]
		scope := w.Namespace
		if scope == "" {
			scope = w.Package // fallback for older callers
		}
		g, ok := groups[scope]
		if !ok {
			g = &group{scope: scope, campaign: w.Campaign, campaignWhen: w.CampaignWhen}
			groups[scope] = g
			order = append(order, scope)
		}
		g.packages = append(g.packages, fmt.Sprintf("%s@%s", w.Package, w.InstalledVersion))
	}

	fmt.Println(formatSection("Heads up — at-risk namespaces"))
	fmt.Printf("  %s\n", formatMuted("Informational only. Your installed versions are not on any IOC list."))
	fmt.Println()
	for _, scope := range order {
		g := groups[scope]
		header := formatPackage(g.scope)
		if g.campaign != "" {
			detail := g.campaign
			if g.campaignWhen != "" {
				detail += ", " + g.campaignWhen
			}
			header += " " + formatMuted("— past compromise: "+detail)
		}
		fmt.Printf("  %s %s\n", infoStyle.Render(infoMark), header)
		for _, pv := range g.packages {
			fmt.Printf("      %s %s\n", formatMuted(bullet), formatMuted(pv))
		}
	}
	fmt.Println()
}

// printSupplyChainAdvisories renders heuristic advisories. Suspicious-unicode
// flags are rare and serious, so each is shown individually; install-script
// flags are common and benign in aggregate, so they're collapsed into a single
// inventory line plus the package list.
func printSupplyChainAdvisories(advisories []types.SupplyChainAdvisory) {
	if len(advisories) == 0 {
		return
	}

	var unicodeFlags, installFlags []types.SupplyChainAdvisory
	for i := range advisories {
		switch advisories[i].Type {
		case "suspicious_unicode":
			unicodeFlags = append(unicodeFlags, advisories[i])
		case "install_script":
			installFlags = append(installFlags, advisories[i])
		}
	}

	if len(unicodeFlags) > 0 {
		fmt.Println(formatSection("Heads up — suspicious package names"))
		for i := range unicodeFlags {
			a := &unicodeFlags[i]
			fmt.Printf("  %s %s\n", infoStyle.Render(infoMark), formatPackageVersion(a.Package, a.InstalledVersion))
			if a.Detail != "" {
				fmt.Printf("      %s %s\n", formatMuted(bullet), formatMuted(a.Detail))
			}
		}
		fmt.Println()
	}

	if len(installFlags) > 0 {
		fmt.Println(formatSection(fmt.Sprintf("Heads up — %d package(s) run install scripts", len(installFlags))))
		fmt.Printf("  %s\n", formatMuted("Informational only. Install scripts are common; review if any are unexpected."))
		for i := range installFlags {
			a := &installFlags[i]
			fmt.Printf("  %s %s\n", formatMuted(bullet), formatMuted(fmt.Sprintf("%s@%s", a.Package, a.InstalledVersion)))
		}
		fmt.Println()
	}
}

func printVulnerabilities(vulnFindings []types.VulnerabilityFinding) {
	if len(vulnFindings) == 0 {
		return
	}

	fmt.Println(formatSection("Vulnerabilities"))
	for i := range vulnFindings {
		v := &vulnFindings[i]
		fmt.Printf("  %s %s\n", severityStyle(v.Severity).Render(bullet), formatPackageVersion(v.Package, v.InstalledVersion))
		fmt.Printf("    %s %s\n", formatLabel("Severity"), formatSeverity(v.Severity))
		fmt.Printf("    %s %s\n", formatLabel("ID"), v.ID)
		fmt.Printf("    %s %s\n", formatLabel("Title"), v.Title)
		if v.PatchedIn != "" {
			fmt.Printf("    %s %s\n", formatLabel("Patched in"), formatVersion(v.PatchedIn))
		}
		fmt.Println()
	}
}

func printLockfiles(lockfiles []types.LockfileInfo) {
	if len(lockfiles) == 0 {
		return
	}

	fmt.Println(formatSection("Lockfiles"))
	for i := range lockfiles {
		lf := &lockfiles[i]
		fmt.Printf("  %s %s (%s, %d deps)\n",
			formatMuted(bullet),
			lf.Path,
			formatMuted(lf.Type),
			lf.Dependencies)
	}
}

func runCheck(scan scanner.Scanner, ecosystem, pkg, version string) {
	result, err := scan.CheckPackage(ecosystem, pkg, version)
	if err != nil {
		printStyledError("%v", err)
		exitFunc(1)
		return
	}

	if outputJSON {
		printJSON(result)
	} else {
		printCheckResult(result, pkg, version)
	}

	// Exit with code 2 if vulnerabilities or supply chain issues found
	if findings.HasCheckFindings(result) {
		exitFunc(2)
	}
}

func printCheckResult(result *types.CheckResult, pkg, version string) {
	// Styled output
	fmt.Println(formatHeader("Package Check"))
	fmt.Println(formatDivider(40))
	fmt.Printf("%s %s\n", formatLabel("Package"), formatPackageVersion(pkg, version))
	fmt.Println()

	// Supply chain status
	if result.SupplyChain.Compromised {
		fmt.Println(formatError("Supply chain compromise detected!"))
		if len(result.SupplyChain.Campaigns) > 0 {
			fmt.Printf("  %s %s\n", formatLabel("Campaigns"), strings.Join(result.SupplyChain.Campaigns, ", "))
		}
		if len(result.SupplyChain.Sources) > 0 {
			fmt.Printf("  %s %s\n", formatLabel("Sources"), strings.Join(result.SupplyChain.Sources, ", "))
		}
	} else {
		fmt.Println(formatSuccess("No supply chain issues"))
	}
	fmt.Println()

	// Vulnerabilities
	if len(result.Vulnerabilities) > 0 {
		fmt.Println(formatSection("Vulnerabilities"))
		for _, v := range result.Vulnerabilities {
			fmt.Printf("  %s [%s] %s\n",
				severityStyle(v.Severity).Render(bullet),
				formatSeverity(v.Severity),
				v.Title)
			fmt.Printf("    %s %s\n", formatLabel("ID"), v.ID)
			if v.PatchedIn != "" {
				fmt.Printf("    %s %s\n", formatLabel("Patched in"), formatVersion(v.PatchedIn))
			}
		}
	} else {
		fmt.Println(formatSuccess("No known vulnerabilities"))
	}

	printCheckTiming(result.Timing)
}

func runRefresh(scan scanner.Scanner, force bool) {
	var result *types.RefreshResult
	var err error

	if outputJSON {
		result, err = scan.Refresh(force)
	} else {
		_ = spinner.New().
			Title("Refreshing IOC database...").
			Action(func() {
				result, err = scan.Refresh(force)
			}).
			Style(spinnerStyle).
			Run()
	}

	if err != nil {
		printStyledError("%v", err)
		exitFunc(1)
		return
	}

	if outputJSON {
		printJSON(result)
		return
	}

	// Styled output
	fmt.Println(formatHeader("Database Refresh"))
	fmt.Println(formatDivider(40))
	fmt.Println()

	if result.Updated {
		fmt.Println(formatSuccess("Database updated"))
	} else {
		fmt.Println(formatMuted("Database already up to date"))
	}

	fmt.Printf("%s %d\n", formatLabel("Packages"), result.PackagesCount)
	fmt.Printf("%s %d\n", formatLabel("Versions"), result.VersionsCount)
	fmt.Printf("%s %d hours\n", formatLabel("Cache age"), result.CacheAgeHours)

	// Per-source results
	if len(result.SourceResults) > 0 {
		fmt.Println()
		fmt.Println(formatSection("Sources"))
		for name, sr := range result.SourceResults {
			printSourceRefreshLine(name, sr)
		}
	}

	if result.Timing != nil {
		fmt.Printf("\n%s %dms\n", formatLabel("Completed in"), result.Timing.TotalMs)
	}
}

func printSourceRefreshLine(name string, sr types.SourceRefreshInfo) {
	status := checkStyle.Render(checkMark)
	if sr.Error != "" {
		status = crossStyle.Render(crossMark)
	}
	if sr.FetchMs > 0 {
		fmt.Printf("  %s %s %s\n", status, name,
			formatMuted(fmt.Sprintf("(%d packages, %dms)", sr.PackageCount, sr.FetchMs)))
	} else {
		fmt.Printf("  %s %s %s\n", status, name,
			formatMuted(fmt.Sprintf("(%d packages)", sr.PackageCount)))
	}
	if sr.Error != "" {
		fmt.Printf("    %s\n", errorStyle.Render(sr.Error))
	}
}

func printScanTiming(timing *types.ScanTiming) {
	if timing == nil {
		return
	}

	fmt.Println()
	fmt.Println(formatSection("Timing"))
	fmt.Printf("  %s %dms\n", formatLabel("Total"), timing.TotalMs)
	fmt.Printf("  %s %dms\n", formatLabel("IOC load"), timing.IOCLoadMs)
	fmt.Printf("  %s %dms\n", formatLabel("Find lockfiles"), timing.FindLockfilesMs)

	for _, lf := range timing.Lockfiles {
		fmt.Printf("  %s %s %s\n",
			formatMuted(bullet),
			lf.Path,
			formatMuted(fmt.Sprintf("(%dms: parse %dms, supply chain %dms, audit %dms)",
				lf.TotalMs, lf.ParseMs, lf.SupplyChainMs, lf.AuditMs)))
	}
}

func printCheckTiming(timing *types.CheckTiming) {
	if timing == nil {
		return
	}

	fmt.Println()
	fmt.Println(formatSection("Timing"))
	fmt.Printf("  %s %dms\n", formatLabel("Total"), timing.TotalMs)
	fmt.Printf("  %s %dms\n", formatLabel("IOC load"), timing.IOCLoadMs)
	fmt.Printf("  %s %dms\n", formatLabel("Supply chain"), timing.SupplyChainMs)
	fmt.Printf("  %s %dms\n", formatLabel("Audit"), timing.AuditMs)
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		log.Fatal(err)
	}
}
