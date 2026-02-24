<div align="center">

# supplyscan

**Security scanner for JavaScript lockfiles — detects supply chain compromises and known vulnerabilities.**

[![GitHub Release](https://img.shields.io/github/v/release/seanhalberthal/supplyscan?style=flat&logo=github)](https://github.com/seanhalberthal/supplyscan/releases/latest)
[![CI](https://img.shields.io/github/actions/workflow/status/seanhalberthal/supplyscan/release.yml?branch=main&style=flat&logo=githubactions&logoColor=white&label=CI)](https://github.com/seanhalberthal/supplyscan/actions/workflows/release.yml)
[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[![macOS](https://img.shields.io/badge/macOS-black?style=flat&logo=apple&logoColor=white)](https://github.com/seanhalberthal/supplyscan/releases/latest)
[![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)](https://github.com/seanhalberthal/supplyscan/releases/latest)
[![Docker](https://img.shields.io/badge/Docker-ghcr.io-2496ED?style=flat&logo=docker&logoColor=white)](https://github.com/seanhalberthal/supplyscan/pkgs/container/supplyscan)
[![MCP](https://img.shields.io/badge/MCP-Compatible-green.svg?style=flat)](https://modelcontextprotocol.io)

[Quick Start](#quick-start) · [Installation](#installation) · [CLI Usage](#cli-usage) · [MCP Server](#mcp-server-integration) · [Data Sources](#data-sources)

</div>

---

## Quick Start

```bash
brew install seanhalberthal/tap/supplyscan

supplyscan scan                       # scan current directory
supplyscan check lodash 4.17.20      # check a specific package
```

---

## Features

- **Supply chain detection** — aggregates IOCs from DataDog, GitHub Advisory Database, and OSV.dev
- **Vulnerability scanning** — integrates with npm audit API for known CVEs
- **Multi-format lockfiles** — npm, Yarn (classic & berry), pnpm, Bun, and Deno
- **Dual interface** — standalone CLI with styled output, or MCP server for AI agents
- **CI/CD friendly** — JSON output mode for scripting and automation
- **Per-source caching** — each IOC source cached independently with configurable TTL

### Supported Lockfiles

| Package Manager | Lockfile |
|-----------------|----------|
| npm | `package-lock.json`, `npm-shrinkwrap.json` |
| Yarn Classic | `yarn.lock` (v1) |
| Yarn Berry | `yarn.lock` (v2+) |
| pnpm | `pnpm-lock.yaml` |
| Bun | `bun.lock` |
| Deno | `deno.lock` |

Built in Go rather than as an npm package, making it immune to npm supply chain attacks by design.

---

## Installation

### Homebrew

```bash
brew install seanhalberthal/tap/supplyscan
```

### Go Install

```bash
go install github.com/seanhalberthal/supplyscan/cmd/supplyscan@latest
```

Requires Go 1.26+ and `$GOPATH/bin` in your PATH.

<details>
<summary><b>Download binary</b></summary>

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

</details>

<details>
<summary><b>Build from source</b></summary>

```bash
git clone https://github.com/seanhalberthal/supplyscan.git
cd supplyscan
go build -o supplyscan ./cmd/supplyscan
mv supplyscan /usr/local/bin/
```

</details>

---

## CLI Usage

The CLI is the default mode — no flags required.

```bash
# Scan current directory
supplyscan scan

# Scan specific path recursively
supplyscan scan /path/to/monorepo --recursive
supplyscan scan /path/to/monorepo -r  # short form

# Scan production dependencies only (exclude devDependencies)
supplyscan scan --no-dev

# Combine flags
supplyscan scan /path/to/monorepo -r --no-dev

# Check a specific package
supplyscan check lodash 4.17.20

# Refresh IOC database
supplyscan refresh
supplyscan refresh --force  # force update even if cache is fresh

# Show status
supplyscan status

# Output raw JSON (for scripting/CI)
supplyscan scan --json
supplyscan check lodash 4.17.20 --json

# Show help
supplyscan help
```

---

## MCP Server Integration

For AI agent integration (Claude Code, Cursor, etc.), supplyscan runs as an MCP server with the `--mcp` flag.

### Claude Code

```bash
brew install seanhalberthal/tap/supplyscan && \
claude mcp add mcp-supplyscan --transport stdio -s user -- supplyscan --mcp
```

### Claude Desktop / Cursor / Other Clients

Add to your MCP config file:

```json
{
  "mcpServers": {
    "mcp-supplyscan": {
      "command": "supplyscan",
      "args": ["--mcp"]
    }
  }
}
```

### MCP Tools

| Tool | Description |
|------|-------------|
| `supplyscan_status` | Scanner version, IOC database info, supported lockfiles |
| `supplyscan_scan` | Scan project directory for compromises and vulnerabilities |
| `supplyscan_check` | Check single package@version |
| `supplyscan_refresh` | Update IOC database from upstream sources |

<details>
<summary><b>Tool parameters</b></summary>

#### `supplyscan_scan`

| Parameter | Type | Description |
|-----------|------|-------------|
| `path` | string | Path to the project directory |
| `recursive` | boolean | Scan subdirectories for lockfiles |
| `include_dev` | boolean | Include dev dependencies |

#### `supplyscan_check`

| Parameter | Type | Description |
|-----------|------|-------------|
| `package` | string | Package name |
| `version` | string | Package version |

#### `supplyscan_refresh`

| Parameter | Type | Description |
|-----------|------|-------------|
| `force` | boolean | Force refresh even if cache is fresh |

</details>

---

## Updating

```bash
# Homebrew
brew upgrade supplyscan

# Go
go install github.com/seanhalberthal/supplyscan/cmd/supplyscan@latest
```

Use `supplyscan status` (CLI) or `supplyscan_status` (MCP) to check your current version.

---

## Data Sources

### IOC Sources (Aggregated)

- **DataDog IOC Database** — [Indicators of Compromise](https://github.com/DataDog/indicators-of-compromise) — Shai-Hulud campaign packages
- **GitHub Advisory Database** — [Security Advisories](https://github.com/advisories) — npm malware advisories (GHSA)
- **OSV.dev** — [Open Source Vulnerabilities](https://osv.dev) — npm malware entries from the MAL ecosystem

### Vulnerability Data

- **npm Audit API** — [Registry audit endpoint](https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities) — known CVEs

---

<details>
<summary><b>Docker</b></summary>

If you prefer containerised execution, supplyscan is available as a Docker image. Note that you must mount your project directory into the container.

### CLI via Docker

```bash
# Scan a directory
docker run --rm -v "$PWD:$PWD:ro" ghcr.io/seanhalberthal/supplyscan:latest \
  scan "$PWD"

# Check a specific package (no mount needed)
docker run --rm ghcr.io/seanhalberthal/supplyscan:latest \
  check lodash 4.17.20
```

### MCP via Docker

```bash
claude mcp add mcp-supplyscan --transport stdio -s user -- \
  docker run --rm -i --pull always \
  -v "$PWD:$PWD:ro" \
  ghcr.io/seanhalberthal/supplyscan:latest --mcp
```

Or add to your MCP config file:

```json
{
  "mcpServers": {
    "mcp-supplyscan": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "--pull", "always",
        "-v", "/path/to/your/projects:/path/to/your/projects:ro",
        "ghcr.io/seanhalberthal/supplyscan:latest",
        "--mcp"
      ]
    }
  }
}
```

Replace `/path/to/your/projects` with the directory containing your projects. The mount uses the same path inside the container so file paths work seamlessly.

</details>

---

## License

[MIT](LICENSE)
