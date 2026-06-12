# Changelog

## 1.1.0 (2026-06-13)

- Redesigned HTML report: findings grouped by severity with one card per finding, full-width governance notes that are never truncated, a severity-driver line explaining contextual escalations, a vendor breakdown, a posture banner colored by level, and a print-friendly layout for save-as-PDF sharing.
- Widened the console summary evidence column.
- Added a step-by-step Windows setup guide for non-technical users.

## 1.0.1 (2026-06-13)

- Deduplicated process findings: one finding per tool with a PID count, instead of one finding per OS process (Electron apps spawn many).
- Deduplicated network findings: one finding per AI endpoint with a session count.
- Added allowlist support in signatures.json: sanctioned tools stay in the inventory at info severity and stop driving posture and exit codes.
- Added Windows (AppData) and macOS (Library) config paths for Claude Desktop and GitHub Copilot.
- Restricted process matching to executable and process name to prevent false positives from command-line arguments; the scanner excludes its own process tree.

## 1.0.0 (2026-06-12)

- Initial release. Seven collectors: running processes, CLI tools on PATH, Python packages, global npm packages, browser extensions (Chrome, Edge, Brave), local model server ports, active sessions to AI API endpoints, and AI credential and config presence.
- Contextual risk model with escalation for active use, configured credentials, and autonomous agent capability.
- JSON and HTML reports, posture-based exit codes for MDM and CI gating.
