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
