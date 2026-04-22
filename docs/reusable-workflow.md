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

The quickstart example keeps `comment-on-pr` at its default `false`. See [Enable sticky PR comment](#enable-sticky-pr-comment) when you want Cremona to maintain a PR comment.

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
| `comment-on-pr` | `false` | Whether to maintain a sticky PR comment on same-repository pull requests |
| `artifact-name` | `cremona-report` | Uploaded artifact name |
| `max-comment-rows` | `5` | Maximum routing rows included in the sticky PR comment |
| `max-hotspots` | `3` | Maximum hotspots included in the sticky PR comment |

## Enable sticky PR comment

Use a Cremona release that includes `comment-on-pr`. That option is not available in `v0.1.1`.

When you enable PR comments, the caller job must grant both `actions: read` and `pull-requests: write`:

```yaml
jobs:
  cremona:
    permissions:
      actions: read
      contents: read
      pull-requests: write
    uses: NeapolitanIcecream/cremona/.github/workflows/reusable-gate.yml@<release-with-comment-on-pr>
    with:
      setup-command: uv sync --group dev
      test-command: uv run coverage run -m pytest -q
      coverage-json-command: uv run coverage json -o coverage.json
      baseline-path: quality/refactor-baseline.json
      comment-on-pr: true
      max-comment-rows: 5
      max-hotspots: 3
```

The sticky comment runs only when all of these are true:

- the workflow is running on a `pull_request` event
- `comment-on-pr` is `true`
- the PR head repository matches the base repository

Fork PRs are skipped. `pull_request_target` is not used.

If the caller workflow overrides permissions and omits `actions: read`, the reusable workflow cannot read the current run metadata it uses to pin the PR comment renderer to the same workflow ref.

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
- The sticky PR comment is also intentionally short. It links reviewers back to the artifact and workflow summary for the full report.
