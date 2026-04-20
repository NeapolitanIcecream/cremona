---
name: cremona-proactive-refactor-audit
description: Use Cremona to locate or bootstrap the Cremona audit tool, run proactive refactoring audits for Python repositories, initialize a baseline, wire Cremona into CI, interpret structural-debt signals, and rank the next refactor targets. Use when Codex needs to answer whether debt is regressing, choose what to refactor next, audit a whole repo or a changed scope, compare against a baseline, inspect `report.md` or `report.json`, or review Cremona hotspots, routing pressure, and dead-code candidates.
---

# Cremona Proactive Refactor Audit

## Overview

Use Cremona as an evidence-first refactor triage pass for Python repositories. Run the scan, read the repo verdict and routing queue, then turn the highest-pressure files into a concrete refactor plan instead of offering generic cleanup advice.

## Decide The Audit Shape

- Audit the whole repository when the user asks what to refactor next, whether structural debt is getting worse, or where to spend cleanup time.
- Audit a narrowed file set when the user is reviewing an in-flight change, validating a risky refactor, or checking whether touched files introduced regressions.
- For first-time adoption, baseline refreshes, or CI gating, use the full configured scope and treat baseline management as part of the task.
- For ordinary analysis, pass coverage JSON when it already exists; it sharpens routing risk, but do not block on generating coverage unless the user asked for it.
- For repository bootstrap or CI work, generate `coverage.json` before the gated scan so `signal_health` can stay `full`.
- Use `--fail-on-regression` for CI-style gating or when the user wants a pass/fail answer.
- Use `--update-baseline` only after debt was genuinely reduced or the stored baseline became obsolete.

## Locate Cremona First

- Run `python3 scripts/locate_cremona.py --target-repo /path/to/target-repo` before the first scan when you are not already inside a known Cremona checkout.
- If the user already gave you an explicit Cremona checkout, set `CREMONA_REPO_PATH=/path/to/cremona` and rerun the script or skip directly to `uv run --project /path/to/cremona cremona scan ...`.
- If the script returns `status=found`, use the reported `scan_command`.
- If the script returns `status=missing`, use the reported `clone_command` to fetch `https://github.com/NeapolitanIcecream/cremona.git`, then rerun the locator and continue with the reported `scan_command`.
- Prefer the locator script over guessing local paths. It checks `cremona` on `PATH`, `CREMONA_REPO_PATH`, the current tree, sibling `cremona` checkouts, and common local checkout directories.

## Run Cremona

- If the locator found a `cremona` executable on `PATH`, run `cremona scan` for the default targets or `cremona scan path/to/repo` for an explicit target.
- If the current workspace is the Cremona checkout, run `uv run cremona scan` for the default targets or `uv run cremona scan path/to/repo` for an explicit target.
- If Cremona lives in another checkout, run `uv run --project /path/to/cremona cremona scan /path/to/target-repo`.
- Add `--coverage-json coverage.json` when a `coverage.py` JSON export already exists.
- Add `--baseline path/to/refactor-baseline.json` to compare against a non-default baseline.
- Add `--out-dir path/to/output/refactor-audit` when the user wants reports somewhere other than the default output directory.
- Add `--profile recoleta` only when the target repository depends on the `recoleta` compatibility routing. Otherwise stay on `generic-python`.
- Read `report.md` first. Open `report.json` only when you need symbol-level evidence, exact priority components, or baseline details.

## Bootstrap And Gate A Repository

- When the user wants Cremona to be self-hosting or repo-native, initialize the baseline from the repository defaults with `cremona scan --update-baseline`.
- Commit `quality/refactor-baseline.json` after that first full-scope scan.
- In CI, generate `coverage.json` from the test run, then run `cremona scan --coverage-json coverage.json --fail-on-regression`.
- If coverage output omits unexecuted files, configure coverage source roots so those files still appear with measured line or branch data instead of `unknown`.
- Do not refresh the baseline just to make CI pass. Baseline updates are for genuine debt reduction or schema changes.

## Read The Report In Priority Order

- Start with `repo_verdict` and summarize `debt_status`, `routing_pressure`, `signal_health`, and whether regressions were detected.
- Read the top items from `agent_routing_queue` next; this is the main file-level prioritization view.
- Use `hotspots` to explain why each file is risky, naming the tools and metrics that matter.
- Treat `recommended_queue` and `recommended_refactor_queue` as subsystem rollups, not the final action list.
- Treat `dead_code_candidates` as review candidates only; never use them as automatic deletion approval.
- When `signal_health` is `partial`, explicitly call out the missing inputs and lower confidence in routing conclusions.

## Turn Findings Into Action

- Recommend the next `3-5` targets unless the user asked for a wider sweep.
- Explain whether each target is driven by static complexity, churn and coupling, ambiguity, dead-code concentration, or low coverage.
- Separate immediate work from monitoring work; do not mix `refactor_now` and `monitor` items into one flat recommendation.
- Propose the smallest safe next step for each target: add characterization tests, extract a helper, split a module, simplify control flow, or delete verified dead code.
- Do not recommend threshold changes as a way to quiet current debt.
- Do not update the baseline to hide regressions.

## Deliverable

Return these items in order:

1. A short repo verdict.
2. The top refactor targets with evidence from the report.
3. Any meaningful baseline regression or resolution.
4. Confidence caveats such as missing coverage or history.
5. A short next-step plan, including tests or baseline updates only when justified.

## Reference

- Read `scripts/locate_cremona.py` when you need machine-readable discovery of the Cremona executable or checkout.
- Read `references/report-interpretation.md` when you need field definitions, ranking heuristics, or ready-made command patterns.
