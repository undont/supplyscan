// Package main implements the supplyscan-mcp server.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/seanhalberthal/supplyscan-mcp/internal/types"
)

func main() {
	// Parse CLI arguments
	cliMode := flag.Bool("cli", false, "Run in CLI mode instead of MCP server")
	flag.Parse()

	if *cliMode {
		runCLI(flag.Args())
		return
	}

	// Run as MCP server
	runServer()
}

func runServer() {
	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "supplyscan-mcp",
			Version: types.Version,
		},
		nil,
	)

	// Register tools
	registerTools(server)

	// Run the server over stdin/stdout
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}

func registerTools(server *mcp.Server) {
	// supplyscan_status - Get scanner version and database info
	mcp.AddTool(server, &mcp.Tool{
		Name:        "supplyscan_status",
		Description: "Get scanner version, IOC database info, and supported lockfile formats",
	}, handleStatus)

	// supplyscan_scan - Full security scan
	mcp.AddTool(server, &mcp.Tool{
		Name:        "supplyscan_scan",
		Description: "Scan a project directory for supply chain compromises and known vulnerabilities",
	}, handleScan)

	// supplyscan_check - Check a single package
	mcp.AddTool(server, &mcp.Tool{
		Name:        "supplyscan_check",
		Description: "Check a single package@version for supply chain compromises and vulnerabilities",
	}, handleCheck)

	// supplyscan_refresh - Update IOC database
	mcp.AddTool(server, &mcp.Tool{
		Name:        "supplyscan_refresh",
		Description: "Update the IOC database from upstream sources",
	}, handleRefresh)
}

// Tool input/output types

type StatusInput struct{}

type StatusOutput struct {
	types.StatusResponse
}

type ScanInput struct {
	Path       string `json:"path" jsonschema:"description=Path to the project directory to scan"`
	Recursive  bool   `json:"recursive,omitempty" jsonschema:"description=Scan subdirectories for lockfiles"`
	IncludeDev bool   `json:"include_dev,omitempty" jsonschema:"description=Include dev dependencies in scan"`
}

type ScanOutput struct {
	types.ScanResult
}

type CheckInput struct {
	Package string `json:"package" jsonschema:"description=Package name to check"`
	Version string `json:"version" jsonschema:"description=Package version to check"`
}

type CheckOutput struct {
	types.CheckResult
}

type RefreshInput struct {
	Force bool `json:"force,omitempty" jsonschema:"description=Force refresh even if cache is fresh"`
}

type RefreshOutput struct {
	types.RefreshResult
}

// Tool handlers

func handleStatus(ctx context.Context, ss *mcp.ServerSession, params *mcp.CallToolParamsFor[StatusInput]) (*mcp.CallToolResultFor[StatusOutput], error) {
	// TODO: Load actual IOC database stats
	status := StatusOutput{
		StatusResponse: types.StatusResponse{
			Version: types.Version,
			IOCDatabase: types.IOCDatabaseStatus{
				Packages:    0,
				Versions:    0,
				LastUpdated: "not loaded",
				Sources:     []string{},
			},
			SupportedLockfiles: types.SupportedLockfiles,
		},
	}

	return &mcp.CallToolResultFor[StatusOutput]{StructuredContent: status}, nil
}

func handleScan(ctx context.Context, ss *mcp.ServerSession, params *mcp.CallToolParamsFor[ScanInput]) (*mcp.CallToolResultFor[ScanOutput], error) {
	input := params.Arguments
	if input.Path == "" {
		return &mcp.CallToolResultFor[ScanOutput]{IsError: true}, fmt.Errorf("path is required")
	}

	// TODO: Implement actual scanning logic
	result := ScanOutput{
		ScanResult: types.ScanResult{
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
		},
	}

	return &mcp.CallToolResultFor[ScanOutput]{StructuredContent: result}, nil
}

func handleCheck(ctx context.Context, ss *mcp.ServerSession, params *mcp.CallToolParamsFor[CheckInput]) (*mcp.CallToolResultFor[CheckOutput], error) {
	input := params.Arguments
	if input.Package == "" {
		return &mcp.CallToolResultFor[CheckOutput]{IsError: true}, fmt.Errorf("package is required")
	}
	if input.Version == "" {
		return &mcp.CallToolResultFor[CheckOutput]{IsError: true}, fmt.Errorf("version is required")
	}

	// TODO: Implement actual check logic
	result := CheckOutput{
		CheckResult: types.CheckResult{
			SupplyChain: types.CheckSupplyChainResult{
				Compromised: false,
			},
			Vulnerabilities: []types.VulnerabilityInfo{},
		},
	}

	return &mcp.CallToolResultFor[CheckOutput]{StructuredContent: result}, nil
}

func handleRefresh(ctx context.Context, ss *mcp.ServerSession, params *mcp.CallToolParamsFor[RefreshInput]) (*mcp.CallToolResultFor[RefreshOutput], error) {
	// TODO: Implement actual refresh logic
	result := RefreshOutput{
		RefreshResult: types.RefreshResult{
			Updated:       false,
			PackagesCount: 0,
			VersionsCount: 0,
			CacheAgeHours: 0,
		},
	}

	return &mcp.CallToolResultFor[RefreshOutput]{StructuredContent: result}, nil
}

// CLI mode

func runCLI(args []string) {
	if len(args) == 0 {
		printCLIUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "status":
		runCLIStatus()
	case "scan":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Error: scan requires a path argument")
			os.Exit(1)
		}
		runCLIScan(args[1], parseCLIScanFlags(args[2:]))
	case "check":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "Error: check requires package and version arguments")
			os.Exit(1)
		}
		runCLICheck(args[1], args[2])
	case "refresh":
		force := len(args) > 1 && args[1] == "--force"
		runCLIRefresh(force)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", args[0])
		printCLIUsage()
		os.Exit(1)
	}
}

func printCLIUsage() {
	fmt.Println(`supplyscan-mcp - JavaScript ecosystem security scanner

Usage:
  supplyscan-mcp                    Run as MCP server (default)
  supplyscan-mcp --cli <command>    Run in CLI mode

Commands:
  status                            Show scanner version and database info
  scan <path> [--recursive]         Scan a project for vulnerabilities
  check <package> <version>         Check a single package@version
  refresh [--force]                 Update IOC database from upstream`)
}

type cliScanOptions struct {
	Recursive  bool
	IncludeDev bool
}

func parseCLIScanFlags(args []string) cliScanOptions {
	opts := cliScanOptions{IncludeDev: true}
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

func runCLIStatus() {
	status := types.StatusResponse{
		Version: types.Version,
		IOCDatabase: types.IOCDatabaseStatus{
			Packages:    0,
			Versions:    0,
			LastUpdated: "not loaded",
			Sources:     []string{},
		},
		SupportedLockfiles: types.SupportedLockfiles,
	}
	printJSON(status)
}

func runCLIScan(path string, opts cliScanOptions) {
	// TODO: Implement actual scanning
	result := types.ScanResult{
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
	printJSON(result)
}

func runCLICheck(pkg, version string) {
	// TODO: Implement actual check
	result := types.CheckResult{
		SupplyChain: types.CheckSupplyChainResult{
			Compromised: false,
		},
		Vulnerabilities: []types.VulnerabilityInfo{},
	}
	printJSON(result)
}

func runCLIRefresh(force bool) {
	// TODO: Implement actual refresh
	result := types.RefreshResult{
		Updated:       false,
		PackagesCount: 0,
		VersionsCount: 0,
		CacheAgeHours: 0,
	}
	printJSON(result)
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		log.Fatal(err)
	}
}
