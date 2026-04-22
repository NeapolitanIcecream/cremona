# Quickstart

Use this guide to get from zero to a first `report.md` in a few minutes.

## Install Cremona

Try it without installing permanently:

```bash
uvx cremona scan /path/to/repo
```

Install it for repeated use:

```bash
pipx install cremona
cremona scan /path/to/repo
```

## Run a first scan

Point Cremona at the repository you want to audit:

```bash
uvx cremona scan /path/to/repo
```

If the repository already has a `pyproject.toml` with `[tool.cremona]`, Cremona uses that configuration. Otherwise it uses the built-in `generic-python` defaults.

## Find the report

By default, Cremona writes these files inside the target repository:

- `output/refactor-audit/report.md`
- `output/refactor-audit/report.json`
- `output/refactor-audit/raw/`

Open `report.md` first.

## Read `repo_verdict`

Start with the `Repo verdict` section in `report.md`.

- `debt_status` tells you whether the current scope regressed.
- `routing_pressure` tells you how urgent the current file queue is.
- `signal_health` tells you whether history and coverage signals were available.

Typical outcomes:

- `stable` + `watch_only`: no structural regression and no immediate target.
- `strained` + `investigate_soon`: debt exists and you should plan the next refactor target.
- `corroding` + `investigate_now`: the current scope regressed or a high-pressure file appeared.

## Optional: add coverage

Coverage sharpens routing risk, but it is not required for the first run.

```bash
uv run coverage run -m pytest -q
uv run coverage json -o coverage.json
uvx cremona scan /path/to/repo --coverage-json /path/to/repo/coverage.json
```

## Optional: bootstrap a baseline

Use a committed baseline when you want CI to fail on structural regressions:

```bash
uvx cremona scan /path/to/repo --update-baseline
git add quality/refactor-baseline.json
```

Next: read [CI gate](ci-gate.md) to wire that baseline into GitHub Actions.
