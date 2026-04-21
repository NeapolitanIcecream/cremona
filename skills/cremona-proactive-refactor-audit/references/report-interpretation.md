# Report Interpretation

## Table Of Contents

- Find Cremona
- Quick read order
- Command patterns
- Key fields
- Interpretation rules
- Response shape

## Find Cremona

Run the locator script first when the current workspace is not obviously the Cremona checkout:

```bash
python3 scripts/locate_cremona.py --target-repo /path/to/repo
python3 scripts/locate_cremona.py --target-repo /path/to/repo --json
```

Expected outcomes:

- `status=found`, `mode=command`: a `cremona` executable is already on `PATH`. Use the returned `scan_command`.
- `status=found`, `mode=repo`: a local Cremona checkout was found. Use `uv run --project /path/to/cremona cremona scan ...`.
- `status=missing`: no executable or checkout was found. Use the returned `clone_command`, then rerun the locator.

Discovery order:

1. `cremona` on `PATH`
2. `CREMONA_REPO_PATH`
3. Current working tree and its parents
4. A sibling directory named `cremona`
5. Common checkout roots such as `~/gits/cremona`, `~/src/cremona`, and `~/projects/cremona`

## Quick Read Order

1. Read `report.md` for the top-line verdict and routing queue.
2. Open `report.json` when you need structured evidence or exact scores.
3. Check `repo_verdict` before proposing any work.
4. Check `agent_routing_queue` before choosing files.
5. Check `hotspots` for symbol-level evidence.
6. Check `baseline_diff` for regressions or resolved debt.
7. Check `dead_code_candidates` last and treat them as review prompts.

## Command Patterns

Current Cremona workspace:

```bash
uv run cremona scan
uv run cremona scan path/to/repo
uv run cremona scan path/to/file.py path/to/other_file.py
```

Separate Cremona checkout:

```bash
uv run --project /path/to/cremona cremona scan /path/to/repo
uv run --project /path/to/cremona cremona scan /path/to/file.py /path/to/dir
```

Bootstrap when missing:

```bash
git clone https://github.com/NeapolitanIcecream/cremona.git /path/to/cremona
uv run --project /path/to/cremona cremona scan /path/to/repo
```

Bootstrap a repository baseline:

```bash
uv run cremona scan --update-baseline
git add quality/refactor-baseline.json
```

`schema_version = 3` is a breaking baseline format. Cremona rejects older
baseline files instead of migrating them in place. Regenerate the baseline
with `uv run cremona scan --update-baseline` after upgrading across a schema
change.

Gate regressions in CI with coverage:

```bash
uv run coverage run -m pytest -q
uv run coverage json -o coverage.json
uv run cremona scan --baseline quality/refactor-baseline.json --coverage-json coverage.json --fail-on-regression
```

Useful switches:

```bash
uv run cremona scan --coverage-json coverage.json
uv run cremona scan --fail-on-regression
uv run cremona scan --baseline quality/refactor-baseline.json
uv run cremona scan --update-baseline
uv run cremona scan --out-dir output/refactor-audit
uv run cremona scan --profile workflow-app
```

## Key Fields

`repo_verdict`

- `debt_status=stable`: No structural debt regression was detected in the current scope.
- `debt_status=strained`: Debt exists, but the current scope did not regress.
- `debt_status=corroding`: Regressions were detected, or a new `refactor_now` hotspot appeared.
- `routing_pressure`: Advisory urgency from the file-level queue.
- `signal_health=partial`: Missing history or coverage reduced routing confidence.

`summary`

- Use for counts only. Do not treat it as sufficient evidence for prioritization.

`hotspots`

- `classification=monitor`: Keep visible but do not elevate ahead of higher-pressure work.
- `classification=refactor_soon`: Refactor when the file is already being touched or the queue also points at it.
- `classification=refactor_now`: Treat as a near-term structural target.
- `tools` and `metrics`: Use these to explain why the hotspot matters.

`agent_routing_queue`

- Use this as the main prioritization surface.
- `priority_band=investigate_now`: Highest urgency.
- `priority_band=investigate_soon`: Worth planning soon.
- `priority_band=watch`: Keep visible, but do not force immediate work.
- `routing_signals`: Built-in and profile-defined signals that added routing pressure for the file.
- `routing_rules_triggered`: Bonus rules that matched and increased the file priority.
- `priority_components.routing_signal_score`: Points contributed by `routing_signals`.
- `priority_components.routing_bonus_score`: Points contributed by triggered routing bonus rules.
- `priority_components`: Break down why a file ranked highly. Useful when two files look similar.

`baseline_diff`

- `new`: A new hotspot or dead-code candidate appeared in scope.
- `worsened`: An existing item became more severe.
- `resolved`: An item present in the baseline is gone or improved enough to drop out.

`dead_code_candidates`

- `high_confidence_candidate`: Stronger review signal, still not deletion permission.
- `review_candidate`: Lower-confidence signal. Confirm by reading call sites, tests, and framework hooks.

`recommended_queue` and `recommended_refactor_queue`

- Use them to summarize subsystem pressure.
- Do not let subsystem rollups replace file-level recommendations.

## Interpretation Rules

- Prefer multi-signal agreement over a single tool warning.
- Treat critical `lizard` or `complexipy` pressure as stronger than `ruff` alone.
- Treat low coverage as routing risk, not automatic proof that refactoring is unsafe.
- In bootstrap or CI scenarios, missing coverage is a workflow gap to fix, not just a caveat to mention.
- Treat churn and coupling as multipliers: a messy file that also changes often is a better refactor candidate than an isolated messy file.
- Treat `signal_health=partial` as a real downgrade in confidence, not a cosmetic warning.
- Keep behavior changes behind tests. Structural refactors still need regression coverage.
- Keep the committed baseline under version control and refresh it only after debt was genuinely reduced or the schema changed.

## Response Shape

Use a compact output structure:

1. Verdict: state `debt_status`, routing pressure, and regression state.
2. Targets: list the top files and the evidence behind each one.
3. Caveats: note missing coverage, missing history, or ambiguous dead-code findings.
4. Next steps: propose the smallest safe refactor sequence and the tests needed to support it.
