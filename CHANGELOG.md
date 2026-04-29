# Changelog

All notable changes to NetWatch AI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `CHANGELOG.md` for open-source project hygiene.
- `.github/workflows/ci.yml` — automated lint and unit tests on every PR.
- `.github/workflows/docker-build.yml` — validates the Docker image builds on every PR.
- `.github/workflows/release.yml` — automated GitHub Release + GHCR Docker image push on version tags.
- `.github/workflows/codeql.yml` — scheduled CodeQL security scanning.
- `.github/ISSUE_TEMPLATE/bug_report.md` and `feature_request.md`.
- `.github/PULL_REQUEST_TEMPLATE.md`.
- `.github/dependabot.yml` for automated dependency updates.
- `.github/CODEOWNERS` assigning review ownership to `@growlf`.
- `VERSION` file (`0.1.0`) as single source of truth for the project version.
- `pyproject.toml` with project metadata and pytest/ruff configuration.
- `requirements-dev.txt` separating development dependencies from runtime.
- `src/agent/config.py` — centralized path constants overridable via environment variables.
- `src/agent/parsers.py` — extracted `parse_routeros_print` from `main.py`.
- `src/agent/agent.py` — extracted background collection loop from `main.py`.
- `tests/unit/test_nmap_scanner.py` — unit tests for nmap scanner helpers.
- `tests/unit/test_kuzu_loader.py` — unit tests for kuzu loader helpers.

### Changed
- **Security**: All Kuzu graph database queries now use parameterized query syntax to prevent Cypher injection attacks.
- **Security**: API routes `/device/{ip}` and `/proxmox/{ip}` now validate the `ip` path parameter to prevent path-traversal attacks.
- **Security**: SSH credential files are now written with `0600` permissions.
- **Logging**: All `print()` calls replaced with structured `logging` calls throughout the agent.
- **Logging**: Silent `except: pass` blocks replaced with `logger.debug()` or `logger.error()` calls.
- **Logging**: Added explicit warnings when `verify_ssl=False` is used for Proxmox connections.
- **Logging**: Added explicit warnings when `paramiko.AutoAddPolicy()` is used.
- `docker-compose.yml`: Removed deprecated `version: '3.8'` key.
- `docker-compose.yml`: Pinned all service images to specific versions.
- `docker-compose.yml`: Added missing `8085` port mapping for the agent web dashboard.
- `src/agent/Dockerfile`: Pinned base image to `python:3.10.14-slim`.
- `src/agent/Dockerfile`: Removed `RUN pytest` — tests now run in CI, not during Docker build.
- `src/agent/requirements.txt`: Pinned all runtime dependencies to specific versions.
- `src/agent/kuzu_loader.py`: Fixed `FACTS_DIR` inconsistency (was mixing relative and absolute paths).
- `src/agent/kuzu_loader.py`: Removed duplicate `import glob`.
- `main.py`: Moved all imports to the top of the file (PEP 8).
- `main.py`: Refactored to use `config.py` constants instead of hardcoded paths.
- `tests/unit/test_parsers.py`: Updated import to use `from parsers import parse_routeros_print`.
- Updated `.gitignore` with standard Python build/cache artifacts.

---

## [0.1.0] — Initial Prototype

### Added
- Docker Compose stack: VictoriaMetrics, Chroma, Kuzu Explorer, and the NetWatch agent.
- Automatic LAN discovery via `nmap`.
- Traceroute-based upstream topology discovery.
- Ansible-based fact collection for MikroTik RouterOS, Proxmox VE, and Linux hosts.
- Kuzu graph database ingestion of discovered hosts, interfaces, and topology.
- Proxmox VE collector for LXC containers and QEMU VMs.
- FastAPI web dashboard with device management UI.
- RouterOS device detail view (DHCP leases, DNS cache, interfaces) via API and SSH fallback.
- Proxmox VE detail view (VMs, LXCs, node status).
- SSH credential management UI.

[Unreleased]: https://github.com/growlf/netyeti-netwatcher/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/growlf/netyeti-netwatcher/releases/tag/v0.1.0
