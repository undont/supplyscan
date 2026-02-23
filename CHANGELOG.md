# Changelog

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
