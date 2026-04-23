# CI gate

Use this guide when you want Cremona to fail CI only when structural debt gets worse.

If you want the shortest GitHub Actions setup, start with [reusable-workflow.md](reusable-workflow.md). This page stays focused on the fully inline recipe.

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

## 5. Write a PR-friendly summary

Copy the repo verdict and the top queue rows into `GITHUB_STEP_SUMMARY` so reviewers can see the result without opening the artifact first.

If you also want a sticky PR comment, prefer the reusable workflow's `comment-on-pr` input from [reusable-workflow.md](reusable-workflow.md). This inline recipe stays focused on the report artifact and workflow summary.

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
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v6
        with:
          python-version: "3.12"
      - uses: astral-sh/setup-uv@v7
      - run: uv sync --group dev
      - run: uv run coverage run -m pytest -q
      - run: uv run coverage json -o coverage.json
      - run: uvx cremona scan --baseline quality/refactor-baseline.json --coverage-json coverage.json --fail-on-regression
      - name: Write Cremona summary
        if: always()
        run: |
          python - <<'PY'
          from pathlib import Path
          import os

          summary_path = Path(os.environ["GITHUB_STEP_SUMMARY"])
          report_path = Path("output/refactor-audit/report.md")
          if not report_path.exists():
              summary_path.write_text("## Cremona report\n\nNo report was produced.\n", encoding="utf-8")
              raise SystemExit(0)

          sections = {}
          current = None
          for line in report_path.read_text(encoding="utf-8").splitlines():
              if line.startswith("## "):
                  current = line[3:]
                  sections[current] = []
                  continue
              if current is not None:
                  sections[current].append(line)

          verdict = "\n".join(sections.get("Repo verdict", [])).strip()
          queue_lines = sections.get("Agent routing queue", [])
          queue_excerpt = []
          row_count = 0
          for line in queue_lines:
              if line.startswith("- History status") or line.startswith("- Lookback days"):
                  queue_excerpt.append(line)
                  continue
              if line.startswith("|"):
                  queue_excerpt.append(line)
                  if line.startswith("| `") or line.startswith("| watch") or line.startswith("| investigate"):
                      row_count += 1
                      if row_count >= 5:
                          break

          lines = [
              "## Cremona report",
              "",
              verdict,
              "",
              "### Top routing rows",
              "",
              *queue_excerpt,
              "",
              "Full Markdown and JSON reports are attached as the `cremona-report` artifact.",
              "",
          ]
          summary_path.write_text("\n".join(lines), encoding="utf-8")
          PY
      - uses: actions/upload-artifact@v7
        if: always()
        with:
          name: cremona-report
          path: output/refactor-audit/
          if-no-files-found: warn
```

## Notes

- Use `fetch-depth: 0` so git-history scoring can see more than the last commit.
- Keep `quality/refactor-baseline.json` in version control.
- Read `report.md` first when the job fails.
- Keep the summary short. The artifact should carry the full report.
- Use the reusable workflow when you want Cremona to keep a sticky PR comment up to date.
