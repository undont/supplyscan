// Package server provides the MCP server implementation for supplyscan-mcp.
package server

import (
	"context"
	"fmt"
	"log"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/seanhalberthal/supplyscan-mcp/internal/scanner"
	"github.com/seanhalberthal/supplyscan-mcp/internal/types"
)

// scan holds the scanner instance for tool handlers.
var scan *scanner.Scanner

// Run starts the MCP server with the given scanner.
func Run(s *scanner.Scanner) {
	scan = s

	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "supplyscan-mcp",
			Version: types.Version,
		},
		nil,
	)

	registerTools(server)

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}

func registerTools(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "supplyscan_status",
		Description: "Get scanner version, IOC database info, and supported lockfile formats",
	}, handleStatus)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "supplyscan_scan",
		Description: "Scan a project directory for supply chain compromises and known vulnerabilities",
	}, handleScan)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "supplyscan_check",
		Description: "Check a single package@version for supply chain compromises and vulnerabilities",
	}, handleCheck)

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
	status := StatusOutput{
		StatusResponse: types.StatusResponse{
			Version:            types.Version,
			IOCDatabase:        scan.GetStatus(),
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

	result, err := scan.Scan(scanner.ScanOptions{
		Path:       input.Path,
		Recursive:  input.Recursive,
		IncludeDev: input.IncludeDev,
	})
	if err != nil {
		return &mcp.CallToolResultFor[ScanOutput]{IsError: true}, err
	}

	return &mcp.CallToolResultFor[ScanOutput]{StructuredContent: ScanOutput{ScanResult: *result}}, nil
}

func handleCheck(ctx context.Context, ss *mcp.ServerSession, params *mcp.CallToolParamsFor[CheckInput]) (*mcp.CallToolResultFor[CheckOutput], error) {
	input := params.Arguments
	if input.Package == "" {
		return &mcp.CallToolResultFor[CheckOutput]{IsError: true}, fmt.Errorf("package is required")
	}
	if input.Version == "" {
		return &mcp.CallToolResultFor[CheckOutput]{IsError: true}, fmt.Errorf("version is required")
	}

	result, err := scan.CheckPackage(input.Package, input.Version)
	if err != nil {
		return &mcp.CallToolResultFor[CheckOutput]{IsError: true}, err
	}

	return &mcp.CallToolResultFor[CheckOutput]{StructuredContent: CheckOutput{CheckResult: *result}}, nil
}

func handleRefresh(ctx context.Context, ss *mcp.ServerSession, params *mcp.CallToolParamsFor[RefreshInput]) (*mcp.CallToolResultFor[RefreshOutput], error) {
	result, err := scan.Refresh(params.Arguments.Force)
	if err != nil {
		return &mcp.CallToolResultFor[RefreshOutput]{IsError: true}, err
	}

	return &mcp.CallToolResultFor[RefreshOutput]{StructuredContent: RefreshOutput{RefreshResult: *result}}, nil
}
