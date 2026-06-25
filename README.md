<div align="center">

# supplyscan

**Scans JavaScript and Python lockfiles for supply-chain compromises and known vulnerabilities.**

[![CI](https://img.shields.io/github/actions/workflow/status/undont/supplyscan/release.yml?branch=main&style=flat&logo=githubactions&logoColor=white&label=CI)](https://github.com/undont/supplyscan/actions/workflows/release.yml)
[![Release](https://img.shields.io/github/v/release/undont/supplyscan?style=flat&logo=github&logoColor=white&label=Release&color=3B82F6)](https://github.com/undont/supplyscan/releases/latest)
[![Licence](https://img.shields.io/github/license/undont/supplyscan?style=flat&label=licence&color=3B82F6)](LICENCE)
[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go&logoColor=white)](https://go.dev)

[![macOS](https://img.shields.io/badge/macOS-supported-6e7681?style=flat&logo=apple&logoColor=white)](https://github.com/undont/supplyscan/releases/latest)
[![Linux](https://img.shields.io/badge/Linux-supported-6e7681?style=flat&logo=linux&logoColor=white)](https://github.com/undont/supplyscan/releases/latest)
[![MCP](https://img.shields.io/badge/MCP-compatible-3B82F6?style=flat)](https://modelcontextprotocol.io)

[Quick Start](#quick-start) · [Installation](#installation) · [CLI Usage](#cli-usage) · [MCP Server](#mcp-server-integration) · [Data Sources](#data-sources)

![supplyscan demo](.demo/demo.gif)

</div>

---

## Quick Start

```bash
brew install undont/tap/supplyscan

supplyscan scan                              # scan current directory
supplyscan check lodash 4.17.20              # check an npm package
supplyscan check django 2.2.0 -e pypi        # check a PyPI package
```

---

## Features

- **Supply-chain detection across npm and PyPI** by aggregating IOCs from DataDog (Shai-Hulud v2 and TeamPCP / Mini Shai-Hulud), GitHub Advisory Database, and OSV.dev, matched per-ecosystem so same-named packages don't collide
- **Vulnerability scanning** via the npm audit API for npm and OSV.dev for PyPI
- **Multi-format lockfile support** across npm, Yarn (classic & berry), pnpm, Bun, Deno, and Python (pip, Poetry, Pipenv, uv, PDM)
- **Heuristic advisories** for packages that run install scripts and for invisible or non-ASCII characters in package names or URLs
- **CLI and MCP modes** in a single binary, switchable with `--mcp`
- **JSON output** for scripting and CI use
- **Per-source caching** with a configurable TTL, so each IOC source refreshes on its own schedule

### Supported Lockfiles

| Package Manager | Lockfile |
|-----------------|----------|
| npm | `package-lock.json`, `npm-shrinkwrap.json` |
| Yarn Classic | `yarn.lock` (v1) |
| Yarn Berry | `yarn.lock` (v2+) |
| pnpm | `pnpm-lock.yaml` |
| Bun | `bun.lock` |
| Deno | `deno.lock` |
| pip | `requirements.txt` |
| Poetry | `poetry.lock` |
| Pipenv | `Pipfile.lock` |
| uv | `uv.lock` |
| PDM | `pdm.lock` |

Written in Go and shipped as a static binary, so the scanner itself can't be compromised by the package ecosystems it scans.

---

## Installation

### Homebrew

```bash
brew install undont/tap/supplyscan
```

### Go Install

```bash
go install github.com/undont/supplyscan/cmd/supplyscan@latest
```

Requires Go 1.26+ and `$GOPATH/bin` in your PATH.

<details>
<summary><b>Download binary</b></summary>

Pre-built binaries are available from [GitHub Releases](https://github.com/undont/supplyscan/releases):

```bash
# macOS (Apple Silicon)
curl -L https://github.com/undont/supplyscan/releases/latest/download/supplyscan-darwin-arm64 \
  -o /usr/local/bin/supplyscan && chmod +x /usr/local/bin/supplyscan

# macOS (Intel)
curl -L https://github.com/undont/supplyscan/releases/latest/download/supplyscan-darwin-amd64 \
  -o /usr/local/bin/supplyscan && chmod +x /usr/local/bin/supplyscan

# Linux (x64)
curl -L https://github.com/undont/supplyscan/releases/latest/download/supplyscan-linux-amd64 \
  -o /usr/local/bin/supplyscan && chmod +x /usr/local/bin/supplyscan
```

</details>

<details>
<summary><b>Build from source</b></summary>

```bash
git clone https://github.com/undont/supplyscan.git
cd supplyscan
go build -o supplyscan ./cmd/supplyscan
mv supplyscan /usr/local/bin/
```

</details>

---

## CLI Usage

The CLI is the default mode; no flags required.

```bash
# Scan current directory
supplyscan scan
supplyscan .  # shorthand

# Scan specific path recursively
supplyscan scan /path/to/monorepo --recursive
supplyscan scan /path/to/monorepo -r  # short form

# Scan production dependencies only (exclude devDependencies)
supplyscan scan --no-dev

# Combine flags
supplyscan scan /path/to/monorepo -r --no-dev

# Check a specific package (npm by default)
supplyscan check lodash 4.17.20

# Check a PyPI package
supplyscan check django 2.2.0 --ecosystem pypi
supplyscan check django 2.2.0 -e pypi  # short form

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
brew install undont/tap/supplyscan && \
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
| `ecosystem` | string | `npm` (default) or `pypi` |

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
go install github.com/undont/supplyscan/cmd/supplyscan@latest
```

Use `supplyscan status` (CLI) or `supplyscan_status` (MCP) to check your current version.

---

## Data Sources

### IOC Sources (Aggregated)

- **[DataDog Indicators of Compromise — Shai-Hulud v2](https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0)** for the original Shai-Hulud worm packages
- **[DataDog Indicators of Compromise — TeamPCP](https://github.com/DataDog/indicators-of-compromise/tree/main/teampcp)** for the Mini Shai-Hulud / TeamPCP campaign (npm rows only)
- **[GitHub Advisory Database](https://github.com/advisories)** for npm malware advisories (GHSA)
- **[OSV.dev](https://osv.dev)** for npm and PyPI malware entries (`MAL-` advisories)

### Vulnerability Data

- **[npm audit API](https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities)** for known CVEs in npm packages
- **[OSV.dev querybatch](https://google.github.io/osv.dev/post-v1-querybatch/)** for known vulnerabilities in PyPI packages

---

## Licence

[MIT](LICENCE)
