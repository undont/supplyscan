# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`supplyscan-mcp` is a Go-based MCP (Model Context Protocol) server that scans JavaScript ecosystem lockfiles for supply chain compromises (e.g., Shai-Hulud campaigns) and known vulnerabilities via the npm audit API. Being implemented in Go rather than as an npm package makes it immune to npm supply chain attacks by design.

## Build and Run Commands

```bash
# Build the binary
go build -o supplyscan-mcp ./cmd/supplyscan-mcp

# Run as MCP server (default, communicates via stdio)
./supplyscan-mcp

# Run in CLI mode
./supplyscan-mcp --cli status
./supplyscan-mcp --cli scan /path/to/project --recursive
./supplyscan-mcp --cli check lodash 4.17.20
./supplyscan-mcp --cli refresh --force

# Run tests
go test ./...

# Docker build
docker build -t supplyscan-mcp .
```

## Architecture

### MCP Server (`cmd/supplyscan-mcp/main.go`)

The entry point runs in two modes:
- **MCP server mode** (default): Communicates via stdio using the official Go MCP SDK
- **CLI mode** (`--cli`): Standalone command-line interface for testing

Four MCP tools are exposed:
- `supplyscan_status` - Scanner version and database info
- `supplyscan_scan` - Full project security scan
- `supplyscan_check` - Check single package@version
- `supplyscan_refresh` - Update IOC database

### Lockfile Parsing (`internal/lockfile/`)

Common interface defined in `lockfile.go`:
```go
type Lockfile interface {
    Type() string              // "npm", "yarn-classic", "yarn-berry", "pnpm", "bun", "deno"
    Path() string
    Dependencies() []Dependency
}
```

`DetectAndParse()` auto-detects format based on filename. Supported formats:
- `package-lock.json`, `npm-shrinkwrap.json` - stdlib JSON parser (v1, v2, v3)
- `yarn.lock` (classic v1) - Line-by-line regex parser
- `yarn.lock` (berry v2+) - YAML parser
- `pnpm-lock.yaml` - YAML parser
- `bun.lock` - JSONC (strip comments, then JSON)
- `deno.lock` - JSON, extract `packages.npm` section

### Shared Types (`internal/types/types.go`)

All data structures for scan results, IOC database, and API responses. Version constant is defined here.

### Planned Structure (Not Yet Implemented)

```
internal/
├── audit/npm.go          # npm registry audit API client
├── supplychain/
│   ├── ioc.go            # Fetch & cache IOCs from DataDog GitHub
│   ├── shaihulud.go      # Shai-Hulud detection logic
│   └── namespaces.go     # At-risk namespace warnings
├── scanner/
│   ├── scanner.go        # Orchestration
│   └── report.go         # Report generation
└── jsonc/jsonc.go        # Strip comments from JSONC
```

## Key Dependencies

- `github.com/modelcontextprotocol/go-sdk` - Official MCP Go SDK
- `gopkg.in/yaml.v3` - YAML parsing for pnpm/yarn-berry (to be added)

## IOC Data Source

Primary source is DataDog's consolidated IOC list:
```
https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/shai-hulud-2.0/consolidated_iocs.csv
```

Cache location: `~/.cache/supplyscan-mcp/`