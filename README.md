# supplyscan

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

## Quick Start

```bash
go install github.com/seanhalberthal/supplyscan/cmd/supplyscan@latest && \
claude mcp add mcp-supplyscan -s user -- supplyscan
```

Restart Claude Code to activate. Requires Go 1.23+ and `$GOPATH/bin` in your PATH.

## Installation

### Go Install (Recommended)

```bash
go install github.com/seanhalberthal/supplyscan/cmd/supplyscan@latest
```

Ensure `$GOPATH/bin` (or `$HOME/go/bin`) is in your PATH.

### Download Binary

Pre-built binaries are available from [GitHub Releases](https://github.com/seanhalberthal/supplyscan/releases):

```bash
# macOS (Apple Silicon)
curl -L https://github.com/seanhalberthal/supplyscan/releases/latest/download/supplyscan-darwin-arm64 \
  -o /usr/local/bin/supplyscan && chmod +x /usr/local/bin/supplyscan

# macOS (Intel)
curl -L https://github.com/seanhalberthal/supplyscan/releases/latest/download/supplyscan-darwin-amd64 \
  -o /usr/local/bin/supplyscan && chmod +x /usr/local/bin/supplyscan

# Linux (x64)
curl -L https://github.com/seanhalberthal/supplyscan/releases/latest/download/supplyscan-linux-amd64 \
  -o /usr/local/bin/supplyscan && chmod +x /usr/local/bin/supplyscan
```

### Build from Source

```bash
git clone https://github.com/seanhalberthal/supplyscan.git
cd supplyscan
go build -o supplyscan ./cmd/supplyscan
mv supplyscan /usr/local/bin/
```

## Configuration

### Claude Code

```bash
claude mcp add mcp-supplyscan -s user -- supplyscan
```

### Claude Desktop / Cursor / Other Clients

Add to your MCP config file:

```json
{
  "mcpServers": {
    "mcp-supplyscan": {
      "command": "supplyscan"
    }
  }
}
```

That's it. No additional configuration required.

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

The binary can also run as a standalone CLI tool for testing or CI integration.

```bash
# Scan current directory
supplyscan --cli scan .

# Scan specific path recursively
supplyscan --cli scan /path/to/monorepo --recursive

# Scan production dependencies only (exclude devDependencies)
supplyscan --cli scan . --no-dev

# Check a specific package
supplyscan --cli check lodash 4.17.20

# Refresh IOC database
supplyscan --cli refresh

# Show status
supplyscan --cli status
```

## Updating

To update to the latest version:

```bash
go install github.com/seanhalberthal/supplyscan/cmd/supplyscan@latest
```

Use `supplyscan_status` (MCP) or `supplyscan --cli status` to check your current version.

## Data Sources

### IOC Sources (Aggregated)

- **DataDog IOC Database**: [Indicators of Compromise](https://github.com/DataDog/indicators-of-compromise) - Shai-Hulud campaign packages
- **GitHub Advisory Database**: [Security Advisories](https://github.com/advisories) - npm malware advisories (GHSA)

### Vulnerability Data

- **npm Audit API**: [Registry audit endpoint](https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities) - known CVEs

---

<details>
<summary><strong>Docker (Alternative)</strong></summary>

If you prefer containerised execution, supplyscan is available as a Docker image. Note that you must mount your project directory into the container.

### Installation

```bash
claude mcp add mcp-supplyscan -s user -- \
  docker run --rm -i --pull always \
  -v "$PWD:$PWD:ro" \
  ghcr.io/seanhalberthal/supplyscan:latest
```

### Manual Configuration

```json
{
  "mcpServers": {
    "mcp-supplyscan": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "--pull", "always",
        "-v", "/path/to/your/projects:/path/to/your/projects:ro",
        "ghcr.io/seanhalberthal/supplyscan:latest"
      ]
    }
  }
}
```

Replace `/path/to/your/projects` with the directory containing your projects. The mount uses the same path inside the container so file paths work seamlessly.

### CLI via Docker

```bash
# Scan a directory
docker run --rm -v "$PWD:$PWD:ro" ghcr.io/seanhalberthal/supplyscan:latest \
  --cli scan "$PWD"

# Check a specific package (no mount needed)
docker run --rm ghcr.io/seanhalberthal/supplyscan:latest \
  --cli check lodash 4.17.20
```

</details>

---

## License

[MIT](LICENSE)