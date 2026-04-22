# CI gate

Use this guide when you want Cremona to fail CI only when structural debt gets worse.

## 1. Create the baseline once

Run a full scan on the repository and commit the baseline:

```bash
uvx cremona scan /path/to/repo --update-baseline
git add quality/refactor-baseline.json
```

Do not refresh the baseline just to make CI pass. Update it only after debt dropped or the schema changed.

## 2. Generate coverage in CI

Cremona can run without coverage, but the routing queue is better when it has coverage data.

```bash
uv run coverage run -m pytest -q
uv run coverage json -o coverage.json
```

Replace the test command with your repository's normal test entrypoint if needed. Keep the `coverage json` export.

## 3. Run the gate

```bash
uvx cremona scan --baseline quality/refactor-baseline.json --coverage-json coverage.json --fail-on-regression
```

## 4. Upload the report artifact

Upload `output/refactor-audit/` so reviewers can open `report.md` even when the job fails.

## GitHub Actions recipe

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
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - uses: astral-sh/setup-uv@v5
      - run: uv sync --group dev
      - run: uv run coverage run -m pytest -q
      - run: uv run coverage json -o coverage.json
      - run: uvx cremona scan --baseline quality/refactor-baseline.json --coverage-json coverage.json --fail-on-regression
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: cremona-report
          path: output/refactor-audit/
```

## Notes

- Use `fetch-depth: 0` so git-history scoring can see more than the last commit.
- Keep `quality/refactor-baseline.json` in version control.
- Read `report.md` first when the job fails.
