# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-08-25

### Added
- Ignore rules via Dockerfile comments: `# check: ignore RULE-ID` (comma-separated list supported)
- Autofix for missing `USER`: inserts non-root user creation (`useradd` / `adduser`) and `USER 10001:10001`
- SARIF 2.1.0 report export (`--sarif FILE`) for GitHub Code Scanning and other tools
- Test fixture `tests/dockerfiles/with_ignore.Dockerfile`
- Expanded testing section in README (ignore, SARIF, USER autofix)

### Changed
- `USER-001` finding is now `auto_fixable` with a suggested fix block
- Tool version reported in SARIF driver metadata: `1.1.0`

### Fixed
- Parser correctly detects `# syntax=docker/dockerfile:...` directive

## [1.0.0] - 2026-08-24

### Added
- Initial release of Dockerfile Security Checker
- 20 security rules (FROM, USER, COPY/ADD, secrets, packages, HEALTHCHECK, multi-stage, CMD, EXPOSE, WORKDIR, syntax)
- Human-readable and JSON reports
- Basic autofix: `ADD` → `COPY`
- Best-practices checklist aligned with CIS Docker Benchmark Section 4
- Algorithm scheme documentation
- Test Dockerfiles (Go, Python, Node, intentional failures)
- MIT license

[1.1.0]: https://github.com/<your-username>/dockerfile-security-checker/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/<your-username>/dockerfile-security-checker/releases/tag/v1.0.0
