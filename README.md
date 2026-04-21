# Cremona

[![CI](https://github.com/NeapolitanIcecream/cremona/actions/workflows/ci.yml/badge.svg)](https://github.com/NeapolitanIcecream/cremona/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](#install)

Cremona is a proactive refactoring audit for Python repositories. It runs
`ruff` C901, `lizard`, `complexipy`, `vulture`, git history, and optional
coverage data, then answers two questions:

- Is structural debt regressing?
- Which files are the best next refactor targets?

## Install

```bash
git clone https://github.com/NeapolitanIcecream/cremona.git
cd cremona
uv sync --group dev
uv run cremona --help
```

Use the bundled Codex skill when you want Codex to run Cremona's repo audit
workflow.

When you start Codex inside this repository, it discovers the repo-scoped
skill automatically from `.agents/skills/cremona-proactive-refactor-audit`.
Invoke it with `$cremona-proactive-refactor-audit`, or let Codex select it
when the task matches the skill description.

To install the same skill into your personal Codex setup, invoke the built-in
installer in Codex and point it at this repository:

```text
$skill-installer install the skill from https://github.com/NeapolitanIcecream/cremona/tree/main/.agents/skills/cremona-proactive-refactor-audit
```

Codex should detect the installed skill automatically. If it does not appear,
restart Codex.

## Run a scan

Scan the current repository:

```bash
uv run cremona scan
```

Scan an explicit path:

```bash
uv run cremona scan /path/to/repo
```

Add coverage data when you already have a `coverage.py` JSON export:

```bash
uv run cremona scan --coverage-json coverage.json
```

Fail the command when the current scope regresses relative to the baseline:

```bash
uv run cremona scan --fail-on-regression
```

## Bootstrap a baseline

Use Cremona as a repo-native gate in three steps:

1. Run a full-scope scan and write the first baseline.
2. Commit `quality/refactor-baseline.json`.
3. In CI, compare the current scan against that baseline.

Initialize the baseline from `pyproject.toml`:

```bash
uv run cremona scan --update-baseline
git add quality/refactor-baseline.json
```

Keep coverage in the regression gate so routing can score coverage risk:

```bash
uv run coverage run -m pytest -q
uv run coverage json -o coverage.json
uv run cremona scan --coverage-json coverage.json --fail-on-regression
```

`schema_version = 3` is a breaking baseline format. Older baselines are not
read. Regenerate them with `cremona scan --update-baseline`.

## Configure a profile

Cremona ships with one built-in profile:

- `generic-python`

Repository-specific behavior belongs in the target repository config. Define a
custom profile under `[tool.cremona.profiles.<name>]` and select it with
`tool.cremona.profile` or `--profile`.

```toml
[tool.cremona]
profile = "workflow-app"
targets = ["app", "tests"]

[tool.cremona.profiles.workflow-app]
base = "generic-python"
queue_order = ["pipeline", "cli", "other"]
fallback_subsystem = "other"

[[tool.cremona.profiles.workflow-app.subsystems]]
name = "pipeline"
include = ["app/pipeline/**"]

[[tool.cremona.profiles.workflow-app.subsystems]]
name = "cli"
include = ["app/cli/**"]

[[tool.cremona.profiles.workflow-app.signals]]
name = "kwargs_bridge_hits"
kind = "regex_count"
pattern = '\\blegacy_[A-Za-z0-9_]*\\b'
points_per = 10
max_points = 6

[[tool.cremona.profiles.workflow-app.routing_bonuses]]
name = "migration_pressure"
points = 4
all = [
  { source = "signal", name = "kwargs_bridge_hits", op = ">=", value = 25 },
  { source = "component", name = "coupling_score", op = ">=", value = 10 },
]

[tool.cremona.profiles.workflow-app.dead_code]
ignored_decorators = ["workflow_entrypoint"]
inherit_default_ignored_decorators = true
```

Profile rules support:

- Subsystem classification with `subsystems` and `fallback_subsystem`
- Queue ordering with `queue_order`
- Custom routing signals with `regex_flag` and `regex_count`
- Cross-signal routing bonuses with `routing_bonuses`
- Extra vulture decorator ignores with `dead_code.ignored_decorators`

Every item in `queue_order` must match a declared subsystem name or the
`fallback_subsystem`.

## Output

Cremona writes these files by default:

- `output/refactor-audit/report.json`
- `output/refactor-audit/report.md`
- `output/refactor-audit/raw/ruff.json`
- `output/refactor-audit/raw/lizard.csv`
- `output/refactor-audit/raw/complexipy.json`
- `output/refactor-audit/raw/vulture.txt`

The JSON report keeps these top-level sections:

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
behind `debt_status`, `routing_pressure`, and the file-level routing queue.
