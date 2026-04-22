# Report format

Use this guide to read Cremona's report in the same order Cremona expects you to act on it.

## Start with `report.md`

`report.md` is the fastest way to read the scan. Open `report.json` only when you need structured data for tooling or deeper inspection.

## `repo_verdict`

`repo_verdict` is the top-line summary for the current scope.

| Field | Meaning | How to use it |
| --- | --- | --- |
| `debt_status` | Whether the current scope regressed | Use this for pass/fail and release decisions |
| `routing_pressure` | Queue urgency | Use this to decide how soon to act |
| `signal_health` | Whether history and coverage signals were available | Lower confidence when it is `partial` |
| `summary` | One-line explanation of the current state | Use this in CI summaries or pull requests |

## `agent_routing_queue`

This is the main file-level priority list.

Each row combines:

- static complexity pressure
- git churn and change frequency
- coupling with other files
- routing signals and routing bonuses
- dead-code concentration
- optional coverage risk

Read the queue from top to bottom. Prefer files with:

- `investigate_now` over `investigate_soon`
- multi-signal pressure over a single warning
- recurring churn plus low coverage over isolated complexity alone

## `recommended_refactor_queue`

This is a subsystem rollup, not the final file list.

Use it to answer questions like:

- Is `src` or `tests` carrying more pressure right now?
- Are urgent files concentrated in one subsystem?

Do not let subsystem counts replace the file-level queue.

## `baseline_diff`

This tells you how the current scope changed relative to the committed baseline.

- `new`: a new hotspot or dead-code candidate appeared
- `worsened`: an existing item got more severe
- `resolved`: an item disappeared or improved enough to drop out

If `has_regressions` is `true`, fix the new pressure or explicitly decide that the baseline should move because debt actually dropped elsewhere.

## How to pick the next file

Use this order:

1. Read `repo_verdict` for regression state and urgency.
2. Pick the highest row in `agent_routing_queue`.
3. Check `hotspots` for the symbols and tools driving that file.
4. Check `baseline_diff` to see whether the pressure is new, worsened, or already known.
5. Treat `dead_code_candidates` as review prompts, not auto-delete instructions.

## When to open `report.json`

Open `report.json` when you need:

- exact priority components for a file
- machine-readable sections for automation
- symbol-level evidence for a hotspot
- baseline details beyond the Markdown summary

For scoring rules and interpretation details, read [methodology.md](methodology.md).
