# supplyscan-mcp

A Go-based MCP (Model Context Protocol) server that scans JavaScript ecosystem lockfiles for supply chain compromises and known vulnerabilities.

Being implemented in Go rather than as an npm package makes it immune to npm supply chain attacks by design.

## Features

- **Supply chain detection**: Identifies packages compromised in the Shai-Hulud campaign using DataDog's IOC database
- **Vulnerability scanning**: Integrates with npm audit API to find known CVEs
- **Multi-format support**: Parses lockfiles from npm, Yarn (classic & berry), pnpm, Bun, and Deno
- **Dual mode**: Runs as an MCP server or standalone CLI tool
- **Automatic caching**: IOC database cached locally with 6-hour TTL

## Supported Lockfiles

| Package Manager | Lockfile |
|-----------------|----------|
| npm | `package-lock.json`, `npm-shrinkwrap.json` |
| Yarn Classic | `yarn.lock` (v1) |
| Yarn Berry | `yarn.lock` (v2+) |
| pnpm | `pnpm-lock.yaml` |
| Bun | `bun.lock` |
| Deno | `deno.lock` |

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
        "-v", "/Users/you/projects:/scan:ro",
        "ghcr.io/seanhalberthal/supplyscan-mcp:latest"
      ]
    }
  }
}
```

Replace `/Users/you/projects` with your projects directory. The `-v` flag mounts it as `/scan` inside the container (read-only).

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

## MCP Tools

### `supplyscan_status`

Get scanner version, IOC database info, and supported lockfile formats.

### `supplyscan_scan`

Scan a project directory for supply chain compromises and known vulnerabilities.

| Parameter | Type | Description |
|-----------|------|-------------|
| `path` | string | Path to the project directory |
| `recursive` | boolean | Scan subdirectories for lockfiles |
| `include_dev` | boolean | Include dev dependencies |

### `supplyscan_check`

Check a single package@version for supply chain compromises and vulnerabilities.

| Parameter | Type | Description |
|-----------|------|-------------|
| `package` | string | Package name |
| `version` | string | Package version |

### `supplyscan_refresh`

Update the IOC database from upstream sources.

| Parameter | Type | Description |
|-----------|------|-------------|
| `force` | boolean | Force refresh even if cache is fresh |

## CLI Mode

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

## Data Sources

- **IOC Database**: [DataDog Indicators of Compromise](https://github.com/DataDog/indicators-of-compromise) (Shai-Hulud campaign)
- **Vulnerability Data**: [npm Registry Audit API](https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities)

## Building

```bash
# Build for current platform
make build

# Cross-compile for all platforms
make build-all

# Run tests
make test

# Run linter
make lint

# Build Docker image
make docker
```
