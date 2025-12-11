# supplyscan-mcp

[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io)

A Go-based MCP (Model Context Protocol) server that scans JavaScript ecosystem lockfiles for supply chain compromises and known vulnerabilities.

Being implemented in Go rather than as an npm package makes it immune to npm supply chain attacks by design.

## Features

- **Supply chain detection**: Identifies compromised packages by aggregating multiple IOC sources (DataDog, GitHub Advisory Database)
- **Vulnerability scanning**: Integrates with npm audit API to find known CVEs
- **Multi-format support**: Parses lockfiles from npm, Yarn (classic & berry), pnpm, Bun, and Deno
- **Dual mode**: Runs as an MCP server or standalone CLI tool
- **Per-source caching**: Each IOC source cached independently with configurable TTL

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

### Claude Code CLI (Recommended)

Install with a single command - no config editing required:

```bash
claude mcp add supplyscan -s user -- \
  docker run --rm -i --pull always \
  -v "$HOME:$HOME:ro" \
  ghcr.io/seanhalberthal/supplyscan-mcp:latest
```

This adds supplyscan to your user-level config, available across all projects. Restart Claude Code to activate.

### Docker (Manual Config)

Alternatively, configure manually. Docker pulls the image automatically on first run.

Skip to [Configuration](#configuration).

### Build from Source

If you prefer a native binary (requires Go 1.23+):

```bash
git clone https://github.com/seanhalberthal/supplyscan-mcp.git
cd supplyscan-mcp
go build -o supplyscan-mcp ./cmd
# Optionally move to PATH
mv supplyscan-mcp /usr/local/bin/
```

### Download Binary

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

These manual configurations are alternatives to the [CLI install](#claude-code-cli-recommended) method above.

### Claude Code / Claude Desktop (Docker)

Add to your MCP config file (`~/.claude.json` for Claude Code, `claude_desktop_config.json` for Claude Desktop):

```json
{
  "mcpServers": {
    "supplyscan": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "--pull", "always",
        "-v", "/Users/you:/Users/you:ro",
        "ghcr.io/seanhalberthal/supplyscan-mcp:latest"
      ]
    }
  }
}
```

Replace `/Users/you` with your home directory. The volume mount uses the same path inside the container so file paths work seamlessly.

**Restrict access** to a specific folder:

```json
"-v", "/Users/you/projects:/Users/you/projects:ro"
```

### Cursor / VS Code (Docker)

These IDEs support workspace variables, which makes configuration simpler:

```json
{
  "mcpServers": {
    "supplyscan": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "--pull", "always",
        "-v", "${workspaceFolder}:${workspaceFolder}:ro",
        "ghcr.io/seanhalberthal/supplyscan-mcp:latest"
      ]
    }
  }
}
```

The workspace folder is mounted at the same path inside the container, so paths work naturally.

### Binary

If using a native binary (built from source or downloaded):

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
docker run --rm --pull always -v /path/to/project:/scan:ro \
  ghcr.io/seanhalberthal/supplyscan-mcp:latest --cli scan /scan

# Check a specific package
docker run --rm --pull always ghcr.io/seanhalberthal/supplyscan-mcp:latest \
  --cli check lodash 4.17.20

# Refresh IOC database
docker run --rm --pull always ghcr.io/seanhalberthal/supplyscan-mcp:latest \
  --cli refresh

# Show status
docker run --rm --pull always ghcr.io/seanhalberthal/supplyscan-mcp:latest \
  --cli status
```

### Binary

```bash
# Scan current directory
supplyscan-mcp --cli scan .

# Scan specific path recursively
supplyscan-mcp --cli scan /path/to/monorepo --recursive

# Scan production dependencies only (exclude devDependencies)
supplyscan-mcp --cli scan . --no-dev

# Check a specific package
supplyscan-mcp --cli check lodash 4.17.20

# Refresh IOC database
supplyscan-mcp --cli refresh

# Show status
supplyscan-mcp --cli status
```

## Data Sources

### IOC Sources (Aggregated)

- **DataDog IOC Database**: [Indicators of Compromise](https://github.com/DataDog/indicators-of-compromise) - Shai-Hulud campaign packages
- **GitHub Advisory Database**: [Security Advisories](https://github.com/advisories) - npm malware advisories (GHSA)

### Vulnerability Data

- **npm Audit API**: [Registry audit endpoint](https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities) - known CVEs

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

## License

[MIT](LICENSE)
