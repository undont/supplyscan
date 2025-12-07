# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`supplyscan-mcp` is a Go-based MCP (Model Context Protocol) server that scans JavaScript ecosystem lockfiles for supply chain compromises (e.g., Shai-Hulud campaigns) and known vulnerabilities via the npm audit API. Being implemented in Go rather than as an npm package makes it immune to npm supply chain attacks by design.

## Build and Run Commands

```bash
# Build the binary
go build -o supplyscan-mcp ./cmd

# Run as MCP server (default, communicates via stdio)
./supplyscan-mcp

# Run in CLI mode
./supplyscan-mcp --cli status
./supplyscan-mcp --cli scan /path/to/project [--recursive] [--no-dev]
./supplyscan-mcp --cli check lodash 4.17.20
./supplyscan-mcp --cli refresh [--force]

# Run tests
go test ./...

# Docker build
docker build -t supplyscan-mcp .
```

## Architecture

### Entry Point (`cmd/main.go`)

Implements two operational modes via a `--cli` flag:
- **MCP server mode** (default): Communicates via stdio using the official Go MCP SDK
- **CLI mode** (`--cli`): Standalone command-line interface for testing

Entry point instantiates a `Scanner` and routes to either `server.Run()` or `cli.Run()`.

### MCP Server (`internal/server/server.go`)

Exposes four MCP tools via `registerTools()`:
- `supplyscan_status` - Scanner version and database info via `handleStatus()`
- `supplyscan_scan` - Full project security scan via `handleScan()`
- `supplyscan_check` - Check single package@version via `handleCheck()`
- `supplyscan_refresh` - Update IOC database via `handleRefresh()`

All handlers interact with the `Scanner` orchestrator.

### CLI Interface (`internal/cli/cli.go`)

Provides command-line access via `Run()` function:
- `status` - Display scanner version and IOC database status
- `scan <path> [--recursive] [--no-dev]` - Scan project directory
- `check <package> <version>` - Check single package
- `refresh [--force]` - Update IOC database

## Scanner Orchestration (`internal/scanner/`)

### Scanner (`scanner.go`)

Core orchestrator that coordinates the security scan. Key methods:
- `New()` - Creates scanner with `Detector` and audit `Client`
- `Scan(ScanOptions)` - Full project security scan:
  1. Finds lockfiles via `lockfile.FindLockfiles()`
  2. Parses each via `lockfile.DetectAndParse()`
  3. Checks supply chain via `detector.CheckDependencies()`
  4. Audits vulnerabilities via `auditClient.AuditDependencies()`
  5. Aggregates findings into `ScanResult`
- `CheckPackage(name, version)` - Single package check:
  1. Checks supply chain via `detector.CheckPackage()`
  2. Audits vulnerabilities via `auditClient.AuditSinglePackage()`
  3. Returns `CheckResult`
- `Refresh(force)` - Delegates to `detector.Refresh(force)`
- `GetStatus()` - Delegates to `detector.GetStatus()`

### Lockfile Parsing (`internal/lockfile/`)

Common `Lockfile` interface defined in `lockfile.go`:
```go
type Lockfile interface {
    Type() string              // "npm", "yarn-classic", "yarn-berry", "pnpm", "bun", "deno"
    Path() string
    Dependencies() []types.Dependency
}
```

Key functions:
- `DetectAndParse(path)` - Auto-detects format and parses:
  - `package-lock.json`, `npm-shrinkwrap.json` → `parseNPM()` (stdlib JSON, v1/v2/v3)
  - `yarn.lock` → `parseYarn()` (line-by-line regex for v1 classic, YAML for v2+ berry)
  - `pnpm-lock.yaml` → `parsePNPM()` (YAML parser)
  - `bun.lock` → `parseBun()` (JSONC strip + JSON)
  - `deno.lock` → `parseDeno()` (JSON, extract `packages.npm` section)
- `FindLockfiles(dir, recursive)` - Finds all lockfiles in a directory, respecting `node_modules` and hidden directories
- `IsLockfile(filename)` - Checks if filename is a recognized lockfile format

## Supply Chain Detection (`internal/supplychain/`)

### Detector (`shaihulud.go`)

Orchestrates IOC loading and supply chain checking. Key methods:
- `NewDetector(opts)` - Creates detector with `IOCCache`
- `EnsureLoaded()` - Ensures IOC database is loaded (soft fail if unavailable)
- `CheckPackage(name, version)` - Checks single package against IOCs, returns `SupplyChainFinding` if compromised
- `CheckDependencies(deps)` - Batch checks dependencies, returns both findings and warnings
- `checkNamespace(name, version)` - Checks if package is from at-risk namespace, returns `SupplyChainWarning` if so
- `Refresh(force)` - Updates IOC database
- `GetStatus()` - Returns current IOC database status as `IOCDatabaseStatus`

### IOC Cache (`ioc.go`)

Manages local IOC database caching. Key components:
- `IOCCache` - Handles fetching and caching IOCs
- `newIOCCache(opts)` - Creates cache with custom cache directory, source URL, or HTTP client
- Fetches from DataDog's consolidated IOC list (see IOC Data Source below)
- Parses CSV format and converts to `types.IOCDatabase`
- Implements 6-hour cache TTL with ETag-based refresh

### Namespace Warnings (`namespaces.go`)

Checks for at-risk namespaces. Key function:
- `isAtRiskNamespace(name)` - Returns true if package is from a known at-risk namespace

## Vulnerability Auditing (`internal/audit/`)

### npm Audit Client (`npm.go`)

Integrates with npm registry audit API. Key methods:
- `NewClient(opts)` - Creates client with custom HTTP client or endpoint
- `AuditDependencies(deps)` - Batch audits dependencies, returns `VulnerabilityFinding` slice
- `AuditSinglePackage(name, version)` - Audits single package, returns `VulnerabilityInfo` slice

Posts dependency data to npm audit endpoint and parses vulnerability metadata.

## Shared Types (`internal/types/`)

Core data structures in `types.go`:
- `Dependency` - Package name, version, dev/optional flags
- `SupplyChainFinding` - Compromised package details with campaign info
- `SupplyChainWarning` - At-risk namespace warning
- `VulnerabilityFinding` - Known vulnerability with severity and patch info
- `ScanResult` - Complete scan output with supply chain and vulnerability findings
- `CheckResult` - Result of checking a single package
- `IOCDatabase` - In-memory IOC data structure
- `IOCDatabaseStatus` - Metadata about IOC database (packages, versions, last updated)
- `StatusResponse` - Output of status tool

Version constant is also defined here.

## Key Dependencies

- `github.com/modelcontextprotocol/go-sdk` - Official MCP Go SDK
- `gopkg.in/yaml.v3` - YAML parsing for pnpm/yarn-berry lockfiles

## IOC Data Source

Primary source is DataDog's consolidated IOC list:
```
https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/shai-hulud-2.0/consolidated_iocs.csv
```

Cache location: `~/.cache/supplyscan-mcp/`
Cache TTL: 6 hours with ETag-based refresh