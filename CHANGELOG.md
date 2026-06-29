# Changelog

## [Unreleased]

- Scan recursively by default: `supplyscan scan <path>` now finds and audits every lockfile in the tree, so pointing at a monorepo root covers all sub-packages with no flag. Use `--no-recursive` (alias `--shallow`) to scan only the top level. The `supplyscan_scan` MCP tool now defaults `recursive` to `true`
- Remove the CLI `--recursive` / `-r` flag (recursion is now the default; pass `--no-recursive` for the old top-level-only behaviour)
- Add workspace-aware coverage: sub-package lockfiles across a monorepo are discovered and reported per workspace
- Report coverage gaps when something can't be audited (unpinned `requirements.txt` entries, a manifest with no lockfile). Gaps are informational by default; `--strict` turns them into a distinct exit code `3`, and a real finding (exit `2`) always takes precedence
- Match npm IOC entries expressed as version ranges (e.g. `< 1.2.3`, `>= 1.0.0, < 2.0.0`) via semver. PyPI continues to match exact pins, enumerated version lists, and all-versions wildcards only (PEP 440 range support is a documented fast-follow)
- Widen the DataDog TeamPCP and GitHub Advisory IOC sources to ingest PyPI (`pip`) rows alongside npm

## [1.15.0](https://github.com/undont/supplyscan/compare/v1.14.0...v1.15.0)

- Add PyPI / Python ecosystem support: parse `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `uv.lock`, and `pdm.lock`, with PEP 503 name normalisation
- Scope IOC matching by ecosystem (`npm` vs `pypi`) so same-named packages across registries don't collide; existing caches rekey on load
- Widen the OSV.dev IOC source to pull the PyPI bulk zip alongside npm
- Add cross-ecosystem vulnerability auditing via OSV.dev querybatch for non-npm dependencies (npm stays on the npm audit API), with CVSS v3 severity mapping
- Add an `ecosystem` argument to the `check` command (`--ecosystem npm|pypi` / `-e`) and the `supplyscan_check` MCP tool
- Add advisory-only heuristics: flag packages that run install scripts and invisible / non-ASCII characters in package names or resolved URLs

## [1.14.0](https://github.com/undont/supplyscan/compare/v1.13.0...v1.14.0)

- Re-release of v1.13.0 with no functional changes (release pipeline re-run on the same commit)

## [1.13.0](https://github.com/undont/supplyscan/compare/v1.12.1...v1.13.0)

- Add `supplyscan .` shorthand for scanning the current directory (equivalent to `supplyscan scan .`)

## [1.12.1](https://github.com/seanhalberthal/supplyscan/compare/v1.12.0...v1.12.1)

- Fix bun lockfile parser mangling package names from nested `parent/child` dependency keys, which silently dropped non-hoisted transitive versions from the audit (e.g. missed vulnerable `postcss` and `brace-expansion` copies)
- Fix pnpm lockfile parser not stripping v6-style `(peer@version)` suffixes, which left versions unparseable (risking false positives) and prevented peer-context duplicates from deduplicating

## [1.12.0](https://github.com/seanhalberthal/supplyscan/compare/v1.11.0...v1.12.0)

- Add DataDog TeamPCP (Mini Shai-Hulud) IOC source for the self-spreading npm worm targeting SAP CAP, TanStack, AntV, and related scopes
- Add at-risk namespace warnings for `@cap-js`, `@tanstack`, `@antv`, `@lint-md`, `@openclaw-cn`, and `@starmind`
- Fix bun lockfile parser treating each entry's integrity hash as a duplicate package version (scans of bun projects were double-counting dependencies)
- Group at-risk namespace notices by scope, name the campaign that put the scope on the list, and lead with "your installed version is not on any IOC list" so the section reads as informational rather than alarming

## [1.11.0](https://github.com/seanhalberthal/supplyscan/compare/v1.10.1...v1.11.0)

- Bump dependencies (notably `modelcontextprotocol/go-sdk` 1.3.1 → 1.6.0)
- Add demo gif to README

## [1.10.1](https://github.com/seanhalberthal/supplyscan/compare/v1.10.0...v1.10.1)

- Fix release workflow to use `inputs.tag` instead of `GITHUB_REF` for `workflow_dispatch` version

## [1.10.0](https://github.com/seanhalberthal/supplyscan/compare/v1.9.1...v1.10.0)

- Extract findings detection into shared package; CLI and MCP server now return exit code 2 / `FindingsError` when vulnerabilities or supply chain issues are found
- Remove ASCII art logo from README

## [1.9.1](https://github.com/seanhalberthal/supplyscan/compare/v1.9.0...v1.9.1)

- Fix spinner style consistency across scan, check, and refresh operations
- Replace briandowns/spinner with charmbracelet/huh spinner

## [1.9.0](https://github.com/seanhalberthal/supplyscan/compare/v1.8.3...v1.9.0)

- Add per-phase timing to scan, check, and refresh operations
- Add stale-while-revalidate for IOC database loading (instant responses when data is cached)

## [1.8.3](https://github.com/seanhalberthal/supplyscan/compare/v1.8.2...v1.8.3)

- Fix version display showing garbled string due to broken sed in release workflow
- Strip `v` prefix from version output (e.g. `1.8.2` instead of `v1.8.2`)

## [1.8.2](https://github.com/seanhalberthal/supplyscan/compare/v1.8.1...v1.8.2)

- Fix OSV source fetching all entries individually (N+1 HTTP requests) by switching to bulk zip download

## [1.8.1](https://github.com/seanhalberthal/supplyscan/compare/v1.8.0...v1.8.1)

- Fix Homebrew tap update being skipped due to GitHub Actions skip-propagation
- Add standalone workflow_dispatch for manually updating Homebrew tap

## [1.8.0](https://github.com/seanhalberthal/supplyscan/compare/v1.7.1...v1.8.0)

- Add Homebrew tap auto-update to release workflow
- Add semver version range filtering to npm audit (skip patched versions)
- Fix script injection vulnerability in CI workflow (use env vars instead of direct interpolation)
- Fix token exposure in Homebrew tap clone URL (use credential helper)
- Scope CI workflow permissions to per-job level (least privilege)
- Restructure README with Homebrew as primary install method

## [1.7.1](https://github.com/seanhalberthal/supplyscan/compare/v1.7.0...v1.7.1)

### Bug Fixes

- Upgrade MCP Go SDK from v0.2.0 to v1.3.1
- Migrate server handlers to v1 API signatures

### Docs

- Update README for Go 1.26+ requirement and OSV.dev source

## [1.7.0](https://github.com/seanhalberthal/supplyscan/compare/v1.6.0...v1.7.0)

### New

- Add OSV.dev as third IOC source for npm malware detection
- Switch npm audit to bulk advisory API for improved performance
- Add version range matching for IOC entries (handles `>= 0` patterns)

### Updates

- Extract Scanner interface for better testability
- Pin golangci-lint version via `go run` (no local install required)
- Add `make help` target

## [1.6.0](https://github.com/seanhalberthal/supplyscan/compare/v1.5.0...v1.6.0)

### Updates

- Add trailing comma support to JSONC parser for better bun.lock compatibility

## [1.5.0](https://github.com/seanhalberthal/supplyscan/compare/v1.4.0...v1.5.0)

### Updates

- Improve status IOC details and fix scan defaults for dev dependencies

## [1.4.0](https://github.com/seanhalberthal/supplyscan/compare/v1.3.0...v1.4.0)

### Updates

- Show per-source IOC database details in status command

## [1.3.0](https://github.com/seanhalberthal/supplyscan/compare/v1.2.1...v1.3.0)

### Updates

- Improve CLI UX with refactored output and British English spelling

## [1.2.1](https://github.com/seanhalberthal/supplyscan/compare/v1.2.0...v1.2.1)

### Bug Fixes

- Auto-detect version from go install build info

## [1.2.0](https://github.com/seanhalberthal/supplyscan/compare/v1.1.1...v1.2.0)

### Breaking Changes

- Rename binary from `supplyscan-mcp` to `supplyscan`

## [1.1.1](https://github.com/seanhalberthal/supplyscan/compare/v1.1.0...v1.1.1)

### Bug Fixes

- Fix build and release workflow when version job creates tag

## [1.1.0](https://github.com/seanhalberthal/supplyscan/compare/v1.0.6...v1.1.0)

### Features

- Add multi-source IOC aggregation with GitHub Advisory support

## [1.0.6](https://github.com/seanhalberthal/supplyscan-mcp/compare/v1.0.5...v1.0.6) (2025-12-07)


### Bug Fixes

* trigger release job when release-please creates a release ([e260af9](https://github.com/seanhalberthal/supplyscan-mcp/commit/e260af995a43c4c23882c265d8a0ac177b311c47))

## [1.0.5](https://github.com/seanhalberthal/supplyscan-mcp/compare/v1.0.4...v1.0.5) (2025-12-07)


### Bug Fixes

* trigger release workflow ([fd12b61](https://github.com/seanhalberthal/supplyscan-mcp/commit/fd12b617e34fe8c5683da684c43de07090b865f3))
* trigger release-please ([0c34ae7](https://github.com/seanhalberthal/supplyscan-mcp/commit/0c34ae7090ebe212cc776e50b25ed2d325579d63))


### Updates

* add semantic versioning with release-please and CI skip patterns ([9fa7562](https://github.com/seanhalberthal/supplyscan-mcp/commit/9fa756272f62eeaaf8d83c7f7b9d100b757614dd))
