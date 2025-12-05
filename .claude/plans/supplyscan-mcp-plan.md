# supplyscan-mcp

> A Go-based MCP server for JavaScript ecosystem security scanning

## Overview

`supplyscan-mcp` scans lockfiles from npm, Yarn, pnpm, Bun, and Deno for:

1. **Supply chain compromises** — Shai-Hulud and future campaigns
2. **Known vulnerabilities** — via npm audit API

By implementing in Go rather than as an npm package, the scanner is immune to npm supply chain attacks by design.

---

## Scope

| Feature | v1 | v2 |
|---------|:--:|:--:|
| Shai-Hulud IOC scanning | ✅ | ✅ |
| npm audit integration | ✅ | ✅ |
| `package-lock.json` | ✅ | ✅ |
| `npm-shrinkwrap.json` | ✅ | ✅ |
| `yarn.lock` (classic v1) | ✅ | ✅ |
| `yarn.lock` (berry v2+) | ✅ | ✅ |
| `pnpm-lock.yaml` | ✅ | ✅ |
| `bun.lock` (text) | ✅ | ✅ |
| `deno.lock` (npm deps only) | ✅ | ✅ |
| `bun.lockb` (binary) | ❌ | Maybe |
| File hash scanning | ❌ | ✅ |
| GitHub Actions scanning | ❌ | ✅ |
| OSV database | ❌ | ✅ |

---

## Project Structure

```
supplyscan-mcp/
├── cmd/
│   └── supplyscan-mcp/
│       └── main.go
├── internal/
│   ├── lockfile/
│   │   ├── lockfile.go          # Interface + detection
│   │   ├── npm.go               # package-lock.json, npm-shrinkwrap.json
│   │   ├── yarn_classic.go      # yarn.lock v1
│   │   ├── yarn_berry.go        # yarn.lock v2+
│   │   ├── pnpm.go              # pnpm-lock.yaml
│   │   ├── bun.go               # bun.lock
│   │   └── deno.go              # deno.lock (npm: deps)
│   ├── audit/
│   │   └── npm.go               # npm registry audit API
│   ├── supplychain/
│   │   ├── ioc.go               # Fetch & cache IOCs
│   │   ├── shaihulud.go         # Shai-Hulud detection
│   │   └── namespaces.go        # At-risk namespace list
│   ├── scanner/
│   │   ├── scanner.go           # Orchestration
│   │   └── report.go            # Report generation
│   ├── jsonc/
│   │   └── jsonc.go             # Strip comments from JSONC
│   └── types/
│       └── types.go
├── Dockerfile
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

---

## Dependencies

```go
require (
    github.com/modelcontextprotocol/go-sdk v0.x.x
    gopkg.in/yaml.v3 v3.0.1
)
```

Minimal footprint. JSONC comment stripping is hand-rolled (~30 lines).

---

## Dockerfile

Multi-stage build for a minimal image (~15-20MB):

```dockerfile
FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /supplyscan-mcp ./cmd/supplyscan-mcp

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /supplyscan-mcp /usr/local/bin/
ENTRYPOINT ["supplyscan-mcp"]
```

Build and publish:

```bash
# Build locally
docker build -t supplyscan-mcp .

# Tag and push to GHCR
docker tag supplyscan-mcp ghcr.io/seanhalberthal/supplyscan-mcp:latest
docker push ghcr.io/seanhalberthal/supplyscan-mcp:latest
```

---

## MCP Tools

### `supplyscan_scan`

Full security scan of a project.

**Input:**
```json
{
  "path": "/path/to/project",
  "recursive": true,
  "include_dev": true
}
```

**Output:**
```json
{
  "summary": {
    "lockfiles_scanned": 2,
    "total_dependencies": 1247,
    "issues": {
      "critical": 1,
      "high": 3,
      "moderate": 12,
      "supply_chain": 2
    }
  },
  "supply_chain": {
    "findings": [
      {
        "severity": "critical",
        "type": "shai_hulud_v2",
        "package": "@postman/schemas",
        "installed_version": "4.32.1",
        "compromised_versions": ["4.32.1"],
        "safe_version": "4.32.2",
        "lockfile": "./package-lock.json",
        "action": "Update immediately and rotate any exposed credentials"
      }
    ],
    "warnings": [
      {
        "type": "namespace_at_risk",
        "package": "@asyncapi/parser",
        "installed_version": "3.0.0",
        "note": "Namespace had compromised packages. This version appears safe but verify."
      }
    ]
  },
  "vulnerabilities": {
    "findings": [
      {
        "severity": "high",
        "package": "lodash",
        "installed_version": "4.17.20",
        "id": "GHSA-35jh-r3h4-6jhm",
        "title": "Prototype Pollution in lodash",
        "patched_in": ">=4.17.21",
        "lockfile": "./package-lock.json"
      }
    ]
  },
  "lockfiles": [
    {
      "path": "./package-lock.json",
      "type": "npm",
      "dependencies": 892
    },
    {
      "path": "./packages/client/yarn.lock",
      "type": "yarn-classic",
      "dependencies": 355
    }
  ]
}
```

### `supplyscan_check`

Check a single package@version.

**Input:**
```json
{
  "package": "lodash",
  "version": "4.17.20"
}
```

**Output:**
```json
{
  "supply_chain": {
    "compromised": false
  },
  "vulnerabilities": [
    {
      "id": "GHSA-35jh-r3h4-6jhm",
      "severity": "high",
      "title": "Prototype Pollution",
      "patched_in": ">=4.17.21"
    }
  ]
}
```

### `supplyscan_refresh`

Update the IOC database from upstream sources.

**Input:**
```json
{
  "force": false
}
```

**Output:**
```json
{
  "updated": true,
  "packages_count": 796,
  "versions_count": 1092,
  "cache_age_hours": 0
}
```

### `supplyscan_status`

Get scanner version, database info, and supported formats.

**Output:**
```json
{
  "version": "1.0.0",
  "ioc_database": {
    "packages": 796,
    "versions": 1092,
    "last_updated": "2025-12-05T10:30:00Z",
    "sources": ["datadog", "wiz", "socket"]
  },
  "supported_lockfiles": [
    "package-lock.json",
    "npm-shrinkwrap.json", 
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "deno.lock"
  ]
}
```

---

## Lockfile Parsers

### Common Interface

```go
type Lockfile interface {
    Type() string              // "npm", "yarn-classic", "yarn-berry", "pnpm", "bun", "deno"
    Path() string
    Dependencies() []Dependency
}

type Dependency struct {
    Name     string
    Version  string
    Dev      bool
    Optional bool
}
```

### Detection Logic

```go
func DetectAndParse(path string) (Lockfile, error) {
    name := filepath.Base(path)
    
    switch name {
    case "package-lock.json", "npm-shrinkwrap.json":
        return parseNPM(path)
    case "yarn.lock":
        return parseYarn(path) // Auto-detects classic vs berry
    case "pnpm-lock.yaml":
        return parsePNPM(path)
    case "bun.lock":
        return parseBun(path)
    case "deno.lock":
        return parseDeno(path)
    default:
        return nil, ErrUnknownFormat
    }
}
```

### Format Notes

| Format | Parser Approach |
|--------|-----------------|
| `package-lock.json` | stdlib JSON, read `packages` map |
| `npm-shrinkwrap.json` | Same as package-lock |
| `yarn.lock` (classic) | Line-by-line regex parser |
| `yarn.lock` (berry) | YAML parser |
| `pnpm-lock.yaml` | YAML parser |
| `bun.lock` | JSONC (strip comments, then JSON) |
| `deno.lock` | JSON, extract `packages.npm` section |

### Yarn Classic Parser

The trickiest format. Structure:

```
# yarn lockfile v1

lodash@^4.17.0:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
  integrity sha512-v2kDE...

"@babel/core@^7.0.0":
  version "7.23.0"
  resolved "..."
```

Parser approach:
1. Read line by line
2. Detect entry headers (unindented lines ending with `:`)
3. Parse indented `version`, `resolved`, `integrity` fields
4. Handle quoted package names (scoped packages like `@babel/core`)

Approximately 100-150 lines of Go.

---

## IOC Data Sources

### Primary Source

DataDog's consolidated IOC list (deduplicated from 7+ vendors):

```
https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/shai-hulud-2.0/consolidated_iocs.csv
```

### Data Structure

```go
type CompromisedPackage struct {
    Name     string   // "@ctrl/tinycolor"
    Versions []string // ["4.1.1", "4.1.2"]
    Sources  []string // ["datadog", "socket", "wiz"]
    Campaign string   // "v1" or "v2"
}
```

### Caching Strategy

```
~/.cache/supplyscan-mcp/
├── iocs.json        # Parsed IOCs indexed by package name
└── meta.json        # Last updated timestamp, ETags
```

- Default TTL: 6 hours
- Auto-refresh on first scan if stale
- ETag/If-Modified-Since for efficient updates
- `supplyscan_refresh` for manual updates

### At-Risk Namespaces

Packages from these namespaces trigger warnings even if the installed version appears safe:

```go
var AtRiskNamespaces = []string{
    "@ctrl",
    "@nativescript-community",
    "@crowdstrike",
    "@asyncapi",
    "@posthog",
    "@postman",
    "@ensdomains",
    "@zapier",
    "@art-ws",
    "@ngx",
}
```

---

## npm Audit Integration

### How It Works

The npm registry exposes a public audit endpoint:

```
POST https://registry.npmjs.org/-/npm/v1/security/audits
```

Send package names and versions, receive known vulnerabilities. No authentication required. Read-only and safe.

### Request Format

```go
type AuditRequest struct {
    Name         string                  `json:"name"`
    Version      string                  `json:"version"`
    Requires     map[string]string       `json:"requires"`
    Dependencies map[string]AuditDep    `json:"dependencies"`
}

type AuditDep struct {
    Version  string            `json:"version"`
    Requires map[string]string `json:"requires,omitempty"`
}
```

---

## Installation

### Docker (Recommended)

No installation required - just configure your MCP client and Docker pulls the image automatically on first run.

Skip to [Configuration](#configuration).

### Alternative: Go Install

If you prefer a native binary and have Go 1.23+ installed:

```bash
go install github.com/seanhalberthal/supplyscan-mcp/cmd/supplyscan-mcp@latest
```

### Alternative: Download Binary

```bash
# macOS (Apple Silicon)
curl -L https://github.com/seanhalberthal/supplyscan-mcp/releases/latest/download/supplyscan-mcp-darwin-arm64 \
  -o /usr/local/bin/supplyscan-mcp && chmod +x /usr/local/bin/supplyscan-mcp

# macOS (Intel)
curl -L https://github.com/seanhalberthal/supplyscan-mcp/releases/latest/download/supplyscan-mcp-darwin-amd64 \
  -o /usr/local/bin/supplyscan-mcp && chmod +x /usr/local/bin/supplyscan-mcp

# Linux (x64)
curl -L https://github.com/seanhalberthal/supplyscan-mcp/releases/latest/download/supplyscan-mcp-linux-amd64 \
  -o /usr/local/bin/supplyscan-mcp && chmod +x /usr/local/bin/supplyscan-mcp

# Windows
# Download from GitHub releases and add to PATH
```

---

## Configuration

### Claude Desktop (Docker)

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "supplyscan": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "/Users/sean/projects:/scan:ro",
        "ghcr.io/seanhalberthal/supplyscan-mcp:latest"
      ]
    }
  }
}
```

Replace `/Users/sean/projects` with your projects directory. The `-v` flag mounts it as `/scan` inside the container (read-only).

To scan your entire home directory:

```json
{
  "mcpServers": {
    "supplyscan": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "${HOME}:/scan:ro",
        "ghcr.io/seanhalberthal/supplyscan-mcp:latest"
      ]
    }
  }
}
```

### Cursor / VS Code (Docker)

These IDEs support workspace variables:

```json
{
  "mcpServers": {
    "supplyscan": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "${workspaceFolder}:/scan:ro",
        "ghcr.io/seanhalberthal/supplyscan-mcp:latest"
      ]
    }
  }
}
```

### Claude Desktop (Binary)

If using `go install` or a downloaded binary:

```json
{
  "mcpServers": {
    "supplyscan": {
      "command": "supplyscan-mcp"
    }
  }
}
```

Or with full path:

```json
{
  "mcpServers": {
    "supplyscan": {
      "command": "/usr/local/bin/supplyscan-mcp"
    }
  }
}
```

---

## CLI Mode (for testing)

The MCP server runs via stdio by default, but includes a CLI mode for standalone testing.

### Docker

```bash
# Scan a directory
docker run --rm -v /path/to/project:/scan:ro ghcr.io/seanhalberthal/supplyscan-mcp:latest \
  --cli scan /scan

# Check a specific package
docker run --rm ghcr.io/seanhalberthal/supplyscan-mcp:latest \
  --cli check lodash 4.17.20

# Refresh IOC database
docker run --rm ghcr.io/seanhalberthal/supplyscan-mcp:latest \
  --cli refresh

# Show status
docker run --rm ghcr.io/seanhalberthal/supplyscan-mcp:latest \
  --cli status
```

### Binary

```bash
# Scan current directory
supplyscan-mcp --cli scan .

# Scan specific path recursively
supplyscan-mcp --cli scan /path/to/monorepo --recursive

# Check a specific package
supplyscan-mcp --cli check lodash 4.17.20

# Refresh IOC database
supplyscan-mcp --cli refresh

# Show status
supplyscan-mcp --cli status
```

---

## Milestones

### Milestone 1: Core Infrastructure
- [ ] Project setup, `go.mod`
- [ ] MCP server skeleton with official Go SDK
- [ ] Basic `supplyscan_status` tool
- [ ] CLI argument parsing
- [ ] Dockerfile

### Milestone 2: Lockfile Parsers
- [ ] `package-lock.json` / `npm-shrinkwrap.json`
- [ ] `yarn.lock` (classic v1)
- [ ] `yarn.lock` (berry v2+)
- [ ] `pnpm-lock.yaml`
- [ ] `bun.lock`
- [ ] `deno.lock`

### Milestone 3: Supply Chain Detection
- [ ] IOC fetcher from DataDog GitHub
- [ ] Local cache with TTL
- [ ] Shai-Hulud package matcher
- [ ] Namespace warnings

### Milestone 4: npm Audit Integration
- [ ] Audit API client
- [ ] Vulnerability matching
- [ ] Severity classification

### Milestone 5: Polish
- [ ] Unified report format
- [ ] `supplyscan_scan` tool (full scan)
- [ ] `supplyscan_check` tool (single package)
- [ ] `supplyscan_refresh` tool
- [ ] README and documentation
- [ ] Makefile with cross-compilation
- [ ] GitHub Actions for Docker builds
- [ ] Release binaries + Docker image

---

## Effort Estimate

| Milestone | Effort |
|-----------|--------|
| 1. Core Infrastructure (inc. Dockerfile) | 1.5 hours |
| 2. Lockfile Parsers | 4 hours |
| 3. Supply Chain Detection | 2 hours |
| 4. npm Audit Integration | 2 hours |
| 5. Polish (inc. GH Actions) | 2.5 hours |
| Testing & edge cases | 2 hours |
| **Total** | **~14 hours** |

---

## Future Enhancements (v2+)

| Feature | Description |
|---------|-------------|
| `bun.lockb` support | Parse binary format (requires porting Zig decoder) |
| File hash scanning | Detect malicious files in `node_modules` |
| GitHub Actions scanning | Detect injected workflows |
| OSV database | Additional vulnerability source |
| SBOM export | CycloneDX/SPDX format |
| Watch mode | Real-time monitoring on lockfile changes |
| CI exit codes | Non-zero exit on vulnerabilities found |

---

## Licence

MIT
