// Package cli provides the command-line interface for supplyscan.
package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/briandowns/spinner"

	"github.com/seanhalberthal/supplyscan/internal/scanner"
	"github.com/seanhalberthal/supplyscan/internal/types"
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
	case "scan":
		path := "."
		flagArgs := args[1:]
		if len(args) >= 2 && !strings.HasPrefix(args[1], "-") {
			path = args[1]
			flagArgs = args[2:]
		}
		runScan(scan, path, parseScanFlags(flagArgs))
	case "check":
		if len(args) < 3 {
			printStyledError("check requires package and version arguments")
			exitFunc(1)
			return
		}
		runCheck(scan, args[1], args[2])
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
	fmt.Println(headerStyle.Render("supplyscan") + " - JavaScript ecosystem security scanner")
	fmt.Println()
	fmt.Println(formatSection("Usage"))
	fmt.Println("  supplyscan <command> [options]    Run CLI commands (default)")
	fmt.Println("  supplyscan --mcp                  Run as MCP server")
	fmt.Println()
	fmt.Println(formatSection("Commands"))
	fmt.Println("  status                            Show scanner version and database info")
	fmt.Println("  scan [path] [--recursive]         Scan a project for vulnerabilities (default: .)")
	fmt.Println("  check <package> <version>         Check a single package@version")
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
		s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
		s.Suffix = fmt.Sprintf(" Scanning %s...", path)
		s.Start()

		result, err = scan.Scan(scanner.ScanOptions{
			Path:       path,
			Recursive:  opts.Recursive,
			IncludeDev: opts.IncludeDev,
		})

		s.Stop()
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
	printScanResult(result)
}

func printScanResult(result *types.ScanResult) {
	fmt.Println(formatHeader("Scan Results"))
	fmt.Println(formatDivider(50))
	fmt.Println()

	printScanSummary(result)
	printIssuesSummary(&result.Summary.Issues)
	printSupplyChainFindings(result.SupplyChain.Findings)
	printSupplyChainWarnings(result.SupplyChain.Warnings)
	printVulnerabilities(result.Vulnerabilities.Findings)
	printLockfiles(result.Lockfiles)
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

func printSupplyChainFindings(findings []types.SupplyChainFinding) {
	if len(findings) == 0 {
		return
	}

	fmt.Println(formatSection("Supply Chain Compromises"))
	for i := range findings {
		f := &findings[i]
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

	fmt.Println(formatSection("Warnings"))
	for i := range warnings {
		w := &warnings[i]
		fmt.Printf("  %s %s\n", warnStyle.Render("!"), formatPackageVersion(w.Package, w.InstalledVersion))
		fmt.Printf("    %s\n", formatMuted(w.Note))
	}
	fmt.Println()
}

func printVulnerabilities(findings []types.VulnerabilityFinding) {
	if len(findings) == 0 {
		return
	}

	fmt.Println(formatSection("Vulnerabilities"))
	for i := range findings {
		v := &findings[i]
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

func runCheck(scan scanner.Scanner, pkg, version string) {
	result, err := scan.CheckPackage(pkg, version)
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
}

func runRefresh(scan scanner.Scanner, force bool) {
	var result *types.RefreshResult
	var err error

	if outputJSON {
		result, err = scan.Refresh(force)
	} else {
		s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
		s.Suffix = " Refreshing IOC database..."
		s.Start()

		result, err = scan.Refresh(force)

		s.Stop()
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
			status := checkStyle.Render(checkMark)
			if sr.Error != "" {
				status = crossStyle.Render(crossMark)
			}
			fmt.Printf("  %s %s (%d packages)\n", status, name, sr.PackageCount)
			if sr.Error != "" {
				fmt.Printf("    %s\n", errorStyle.Render(sr.Error))
			}
		}
	}
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		log.Fatal(err)
	}
}
