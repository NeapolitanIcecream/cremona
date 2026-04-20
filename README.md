# Cremona

[![CI](https://github.com/NeapolitanIcecream/cremona/actions/workflows/ci.yml/badge.svg)](https://github.com/NeapolitanIcecream/cremona/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](#install)

Cremona is a proactive refactoring audit for Python repositories. It combines
`ruff` C901, `lizard`, `complexipy`, `vulture`, git history, and optional
coverage data into one report that answers two questions:

- Is structural debt regressing?
- Which files are the best next refactor targets?

The first release was extracted from `recoleta` and keeps a built-in
`recoleta` profile for compatibility, but the default behavior is generic for
Python repositories.

## Install

```bash
git clone https://github.com/NeapolitanIcecream/cremona.git
cd cremona
uv sync --group dev
uv run cremona --help
```

## Run a scan

Scan the current repository with default settings:

```bash
uv run cremona scan
```

Scan a specific path:

```bash
uv run cremona scan /path/to/repo
```

Add coverage data:

```bash
uv run cremona scan --coverage-json coverage.json
```

Fail the command when the scan introduces structural regressions relative to a
baseline:

```bash
uv run cremona scan --fail-on-regression
```

## Bootstrap a repository

Use Cremona as a repo-native gate in three steps:

1. Generate the first baseline from the full configured scope.
2. Commit `quality/refactor-baseline.json`.
3. In CI, fail the build when the current scan regresses relative to that
   baseline.

Initialize the baseline with the defaults from `pyproject.toml`:

```bash
uv run cremona scan --update-baseline
git add quality/refactor-baseline.json
```

Generate coverage data before running the regression gate so routing can score
coverage risk without dropping to partial signal health:

```bash
uv run coverage run -m pytest -q
uv run coverage json -o coverage.json
uv run cremona scan --coverage-json coverage.json --fail-on-regression
```

For this repository, `[tool.coverage.run]` is configured to measure `src` and
`tests` with branch coverage so `coverage.json` includes files that were not
executed.

Update the baseline only after debt was actually reduced, or when a report
schema change makes the old baseline obsolete.

## Profiles

Cremona ships with two profiles:

- `generic-python`: default behavior for normal Python repositories.
- `recoleta`: preserves `recoleta` subsystem routing and compatibility signals.

Select a profile on the command line:

```bash
uv run cremona scan --profile recoleta
```

Or in `pyproject.toml`:

```toml
[tool.cremona]
profile = "generic-python"
targets = ["src"]
```

## Output

Cremona writes these files by default:

- `output/refactor-audit/report.json`
- `output/refactor-audit/report.md`
- `output/refactor-audit/raw/ruff.json`
- `output/refactor-audit/raw/lizard.csv`
- `output/refactor-audit/raw/complexipy.json`
- `output/refactor-audit/raw/vulture.txt`

The JSON report keeps the current high-value sections:

- `summary`
- `tool_summaries`
- `history_summary`
- `hotspots`
- `dead_code_candidates`
- `agent_routing_queue`
- `recommended_queue`
- `recommended_refactor_queue`
- `baseline_diff`
- `repo_verdict`

## Methodology

Read [docs/methodology.md](docs/methodology.md) for the interpretation rules
behind `debt_status`, `routing_pressure`, and the agent routing queue.

## Provenance

Read [docs/provenance.md](docs/provenance.md) for the extraction source and
migration history from `recoleta`.
