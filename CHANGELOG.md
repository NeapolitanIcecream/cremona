# Changelog

All notable changes to Cremona are documented here.

## [0.1.0] - 2026-04-22

### Highlights

- Published the first public release shape for `uvx cremona scan /path/to/repo`, `pipx install cremona`, and wheel-based installs.
- Reworked the public README around quickstart, example output, Codex workflow, and CI adoption.
- Added task-focused docs for quickstart, CI gating, report interpretation, Codex usage, troubleshooting, and release operations.
- Added contributor and trust files, issue and PR templates, Dependabot, and an OpenSSF Scorecard workflow.

### Breaking changes

- Baselines use `schema_version = 3`. Regenerate older baselines with `cremona scan --update-baseline`.
