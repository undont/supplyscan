// Package server provides the MCP server implementation for supplyscan.
package server

import (
	"context"
	"fmt"
	"log"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/seanhalberthal/supplyscan/internal/scanner"
	"github.com/seanhalberthal/supplyscan/internal/types"
)

// scan holds the scanner instance for tool handlers.
var scan scanner.Scanner

// Run starts the MCP server with the given scanner.
func Run(s scanner.Scanner) {
	scan = s

	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "supplyscan",
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

type statusInput struct{}

type statusOutput struct {
	types.StatusResponse
}

type scanInput struct {
	Path       string `json:"path" jsonschema:"path to the project directory to scan"`
	Recursive  bool   `json:"recursive,omitempty" jsonschema:"scan subdirectories for lockfiles"`
	IncludeDev *bool  `json:"include_dev,omitempty" jsonschema:"include dev dependencies in scan (default: true)"`
}

type scanOutput struct {
	types.ScanResult
}

type checkInput struct {
	Package string `json:"package" jsonschema:"package name to check"`
	Version string `json:"version" jsonschema:"package version to check"`
}

type checkOutput struct {
	types.CheckResult
}

type refreshInput struct {
	Force bool `json:"force,omitempty" jsonschema:"force refresh even if cache is fresh"`
}

type refreshOutput struct {
	types.RefreshResult
}

// Tool handlers

func handleStatus(_ context.Context, _ *mcp.CallToolRequest, _ statusInput) (*mcp.CallToolResult, statusOutput, error) {
	status := statusOutput{
		StatusResponse: types.StatusResponse{
			Version:            types.Version,
			IOCDatabase:        scan.GetStatus(),
			SupportedLockfiles: types.SupportedLockfiles,
		},
	}

	return nil, status, nil
}

func handleScan(_ context.Context, _ *mcp.CallToolRequest, input scanInput) (*mcp.CallToolResult, scanOutput, error) {
	if input.Path == "" {
		return nil, scanOutput{}, fmt.Errorf("path is required")
	}

	// Default to including dev dependencies (matches CLI behaviour)
	includeDev := true
	if input.IncludeDev != nil {
		includeDev = *input.IncludeDev
	}

	result, err := scan.Scan(scanner.ScanOptions{
		Path:       input.Path,
		Recursive:  input.Recursive,
		IncludeDev: includeDev,
	})
	if err != nil {
		return nil, scanOutput{}, err
	}

	return nil, scanOutput{ScanResult: *result}, nil
}

func handleCheck(_ context.Context, _ *mcp.CallToolRequest, input checkInput) (*mcp.CallToolResult, checkOutput, error) {
	if input.Package == "" {
		return nil, checkOutput{}, fmt.Errorf("package is required")
	}
	if input.Version == "" {
		return nil, checkOutput{}, fmt.Errorf("version is required")
	}

	result, err := scan.CheckPackage(input.Package, input.Version)
	if err != nil {
		return nil, checkOutput{}, err
	}

	return nil, checkOutput{CheckResult: *result}, nil
}

func handleRefresh(_ context.Context, _ *mcp.CallToolRequest, input refreshInput) (*mcp.CallToolResult, refreshOutput, error) {
	result, err := scan.Refresh(input.Force)
	if err != nil {
		return nil, refreshOutput{}, err
	}

	return nil, refreshOutput{RefreshResult: *result}, nil
}
