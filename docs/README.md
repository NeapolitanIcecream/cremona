# Cremona docs

Start here if you want to install Cremona, run a first scan, wire it into CI, or use it with Codex.

## Start with one of these guides

- [Quickstart](quickstart.md): install Cremona, run a scan, open `report.md`, and read `repo_verdict`.
- [Reusable workflow](reusable-workflow.md): call Cremona from GitHub Actions without copying the whole job into your repository, and optionally keep a sticky PR comment updated.
- [CI gate](ci-gate.md): bootstrap a baseline and fail CI when structural debt regresses.
- [Report format](report-format.md): understand `repo_verdict`, `agent_routing_queue`, `recommended_refactor_queue`, and `baseline_diff`.
- [Codex skill](codex-skill.md): use the bundled skill to turn the report into a refactor plan.
- [Troubleshooting](troubleshooting.md): fix the common setup and signal-health problems.

## Positioning and evaluation

- [Comparison](comparison.md): compare Cremona with Ruff-only workflows, standalone complexity tools, and broader code-quality platforms.
- [FAQ](faq.md): answer the common adoption questions about coverage, baselines, dead code, and repository scope.
- [Case study: Typer](case-study-typer.md): see a real scan against `fastapi/typer` from April 22, 2026.

## Reference

- [Methodology](methodology.md): scoring and interpretation rules.
- [Release checklist](release-checklist.md): ship a release, publish to PyPI, and verify install paths.
