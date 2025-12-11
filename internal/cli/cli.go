// Package cli provides the command-line interface for supplyscan-mcp.
package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/seanhalberthal/supplyscan-mcp/internal/scanner"
	"github.com/seanhalberthal/supplyscan-mcp/internal/types"
)

const errorFormat = "Error: %v\n"

// exitFunc is the function used to exit the program. Override in tests.
var exitFunc = os.Exit

// Run executes the CLI with the given scanner and arguments.
func Run(scan *scanner.Scanner, args []string) {
	if len(args) == 0 {
		printUsage()
		exitFunc(1)
		return
	}

	switch args[0] {
	case "status":
		runStatus(scan)
	case "scan":
		if len(args) < 2 {
			_, _ = fmt.Fprintln(os.Stderr, "Error: scan requires a path argument")
			exitFunc(1)
			return
		}
		runScan(scan, args[1], parseScanFlags(args[2:]))
	case "check":
		if len(args) < 3 {
			_, _ = fmt.Fprintln(os.Stderr, "Error: check requires package and version arguments")
			exitFunc(1)
			return
		}
		runCheck(scan, args[1], args[2])
	case "refresh":
		force := len(args) > 1 && args[1] == "--force"
		runRefresh(scan, force)
	default:
		_, _ = fmt.Fprintf(os.Stderr, "Unknown command: %s\n", args[0])
		printUsage()
		exitFunc(1)
		return
	}
}

func printUsage() {
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

type scanOptions struct {
	Recursive  bool
	IncludeDev bool
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

func runStatus(scan *scanner.Scanner) {
	status := types.StatusResponse{
		Version:            types.Version,
		IOCDatabase:        scan.GetStatus(),
		SupportedLockfiles: types.SupportedLockfiles,
	}
	printJSON(status)
}

func runScan(scan *scanner.Scanner, path string, opts scanOptions) {
	result, err := scan.Scan(scanner.ScanOptions{
		Path:       path,
		Recursive:  opts.Recursive,
		IncludeDev: opts.IncludeDev,
	})
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, errorFormat, err)
		exitFunc(1)
		return
	}
	printJSON(result)
}

func runCheck(scan *scanner.Scanner, pkg, version string) {
	result, err := scan.CheckPackage(pkg, version)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, errorFormat, err)
		exitFunc(1)
		return
	}
	printJSON(result)
}

func runRefresh(scan *scanner.Scanner, force bool) {
	result, err := scan.Refresh(force)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, errorFormat, err)
		exitFunc(1)
		return
	}
	printJSON(result)
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		log.Fatal(err)
	}
}
