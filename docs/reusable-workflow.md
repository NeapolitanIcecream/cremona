# Reusable workflow

Use this guide when you want to add Cremona to GitHub Actions without copying the whole CI job into your repository.

## Quickstart

Create a workflow in the target repository:

```yaml
name: cremona

on:
  pull_request:
  push:
    branches: ["main"]

permissions:
  contents: read

jobs:
  cremona:
    permissions:
      contents: read
    uses: NeapolitanIcecream/cremona/.github/workflows/reusable-gate.yml@v0.1.1
    with:
      setup-command: uv sync --group dev
      test-command: uv run coverage run -m pytest -q
      coverage-json-command: uv run coverage json -o coverage.json
      baseline-path: quality/refactor-baseline.json
```

This workflow:

- checks out the target repository with full history
- installs Python and `uv`
- runs your setup and test commands
- runs `uvx cremona scan`
- writes a short GitHub step summary
- uploads the full report directory as an artifact

## When to use it

Use the reusable workflow when:

- you want the shortest GitHub Actions setup
- your repository already has a normal test and coverage command
- you want a shared adoption path across many repositories

Use [ci-gate.md](ci-gate.md) instead when you want full control over every step in the workflow file.

## Inputs

| Input | Default | What it controls |
| --- | --- | --- |
| `python-version` | `3.12` | Python version used in the workflow |
| `working-directory` | `.` | Directory where setup, tests, and scan run |
| `setup-command` | `uv sync --group dev` | Repository preparation step before tests |
| `test-command` | `uv run coverage run -m pytest -q` | Command that produces coverage data |
| `coverage-json-command` | `uv run coverage json -o coverage.json` | Command that writes the coverage JSON file |
| `coverage-json-path` | `coverage.json` | Path passed to `--coverage-json` |
| `baseline-path` | `quality/refactor-baseline.json` | Path passed to `--baseline` |
| `out-dir` | `output/refactor-audit` | Directory where the report is written |
| `extra-scan-args` | empty | Extra arguments forwarded to `cremona scan` |
| `fail-on-regression` | `true` | Whether the workflow exits non-zero on regression |
| `upload-artifact` | `true` | Whether the report directory is uploaded |
| `artifact-name` | `cremona-report` | Uploaded artifact name |

## Example: repository that does not use `uv`

Override the repo-specific commands and keep Cremona itself on `uvx`:

```yaml
jobs:
  cremona:
    permissions:
      contents: read
    uses: NeapolitanIcecream/cremona/.github/workflows/reusable-gate.yml@v0.1.1
    with:
      setup-command: python -m pip install -U pip && python -m pip install -r requirements-dev.txt
      test-command: python -m coverage run -m pytest -q
      coverage-json-command: python -m coverage json -o coverage.json
      baseline-path: quality/refactor-baseline.json
```

## Notes

- Keep `quality/refactor-baseline.json` in version control.
- Use `extra-scan-args` when you need flags such as `--profile`.
- The summary is intentionally short. Reviewers can open the uploaded artifact for the full Markdown and JSON reports.
