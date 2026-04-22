# Cremona

[![CI](https://github.com/NeapolitanIcecream/cremona/actions/workflows/ci.yml/badge.svg)](https://github.com/NeapolitanIcecream/cremona/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](#install-from-source-for-contributors)

Cremona turns Python structural-debt signals into an agent-ready refactoring queue and CI regression gate.

It combines `ruff` C901, `lizard`, `complexipy`, `vulture`, git history, and optional coverage data so you can answer two questions quickly:

- Is structural debt regressing?
- Which files should be refactored next?

## 60-second quickstart

Run Cremona against a repository without cloning this repo first:

```bash
uvx cremona scan /path/to/repo
```

Keep it installed for repeated use:

```bash
pipx install cremona
cremona scan /path/to/repo
```

By default, Cremona writes these files in the target repository:

- `output/refactor-audit/report.md`
- `output/refactor-audit/report.json`
- `output/refactor-audit/raw/`

Start with `report.md`. It gives you the repo verdict, the file queue, the top hotspots, and the baseline diff in one pass.

## Why Cremona

- `ruff` tells you where control flow is growing.
- `lizard` and `complexipy` show which functions are hard to change safely.
- Git history shows churn and coupling.
- Coverage data shows where change risk is still high.
- Cremona turns those signals into a refactoring queue instead of a pile of unrelated warnings.

## Example verdict and queue

This excerpt comes from Cremona's current self-host report.

- Repo verdict: `stable`
- Routing pressure: `watch_only`
- Signal health: `full`

| Priority | Score | File | Why it stays visible |
| --- | ---: | --- | --- |
| `watch` | 33 | `src/cremona/core/engine.py` | `5` commits, `2444` churn, branch coverage `0.82`, coupled with `tests/test_cremona_scan.py` |
| `watch` | 32 | `tests/test_cremona_scan.py` | `8` commits, `4168` churn, branch coverage `1.00`, coupled with `src/cremona/core/engine.py` |
| `watch` | 27 | `src/cremona/scan.py` | `2` commits, `5870` churn, line coverage `1.00`, coupled with `src/cremona/core/__init__.py` |

On a repository with active structural pressure, the same queue will surface `investigate_soon` and `investigate_now` rows.

## Codex and agent workflow

Use the bundled Codex skill when you want an agent to turn the report into a concrete refactor plan.

1. Run `uvx cremona scan /path/to/repo`.
2. Open `report.md` and choose the top file from `agent_routing_queue`.
3. Ask Codex to make the smallest safe refactor.
4. Run Cremona again.
5. Update the baseline only when debt actually dropped or the schema changed.

When you start Codex inside this repository, it discovers the repo-scoped skill automatically from `.agents/skills/cremona-proactive-refactor-audit`.

To install the same skill into your personal Codex setup:

```text
$skill-installer install the skill from https://github.com/NeapolitanIcecream/cremona/tree/main/.agents/skills/cremona-proactive-refactor-audit
```

Read [docs/codex-skill.md](docs/codex-skill.md) for the full workflow.

## CI gate

Bootstrap the first baseline:

```bash
uvx cremona scan /path/to/repo --update-baseline
git add quality/refactor-baseline.json
```

Use coverage in the gate so routing can score change risk:

```bash
uv run coverage run -m pytest -q
uv run coverage json -o coverage.json
uvx cremona scan --baseline quality/refactor-baseline.json --coverage-json coverage.json --fail-on-regression
```

Read [docs/reusable-workflow.md](docs/reusable-workflow.md) for the fastest GitHub Actions integration, or [docs/ci-gate.md](docs/ci-gate.md) if you want the full custom recipe.

The reusable workflow can also maintain a sticky PR comment with the repo verdict, top routing rows, and top hotspots. See `comment-on-pr` in [docs/reusable-workflow.md](docs/reusable-workflow.md) for the same-repository `pull_request` constraints and required `pull-requests: write` permission.

## Install from source for contributors

Use the source install when you are changing Cremona itself.

```bash
git clone https://github.com/NeapolitanIcecream/cremona.git
cd cremona
uv sync --group dev
uv run cremona --help
```

## Read next

- [docs/README.md](docs/README.md)
- [docs/quickstart.md](docs/quickstart.md)
- [docs/report-format.md](docs/report-format.md)
- [docs/reusable-workflow.md](docs/reusable-workflow.md)
- [docs/comparison.md](docs/comparison.md)
- [docs/faq.md](docs/faq.md)
- [docs/case-study-typer.md](docs/case-study-typer.md)
- [docs/methodology.md](docs/methodology.md)
- [CHANGELOG.md](CHANGELOG.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
