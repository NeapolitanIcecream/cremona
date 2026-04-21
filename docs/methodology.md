# Methodology

Use Cremona when you need a clear answer to two questions:

1. Is the repository accumulating structural debt?
2. What should be refactored next?

## Workflow

1. Run `ruff` first to confirm the normal lint baseline.
2. Run `cremona scan` on the whole repository, or narrow the scope to the files
   you are actively changing.
3. Pass `--coverage-json` when coverage data exists.
4. Read `report.md` first for the repo verdict and routing queue.
5. Read `report.json` when you need symbol-level evidence or baseline details.

## Bootstrap a baseline

When you adopt Cremona on a repository for the first time:

1. Run `cremona scan --update-baseline` on the full configured scope.
2. Commit `quality/refactor-baseline.json`.
3. In CI, generate `coverage.json` from the test run and pass it to
   `cremona scan --coverage-json coverage.json --fail-on-regression`.

That keeps regressions gated against a committed baseline while preserving the
coverage signal used in routing.

Cremona currently writes `schema_version = 3`. Older baselines are rejected
instead of migrated in place, so regenerate them with
`cremona scan --update-baseline` after upgrading across a schema break.

If `coverage.json` omits files that were not executed, configure coverage
source roots up front so those files still appear with measured line or branch
data instead of `unknown`.

## Interpretation rules

- `ruff` C901 is the early warning signal for control-flow growth.
- `lizard` measures structural pressure through `CCN`, `NLOC`, and parameter
  count.
- `complexipy` is the main signal for "hard to change safely."
- `vulture` only produces review candidates. It is not permission to delete
  code automatically. The default threshold is conservative by design; it is a
  review gate, not a wide-recall dead-code sweep.
- The file-level routing queue is the main prioritization view. It combines
  static pressure, change frequency, churn, coupling, routing signals,
  dead-code concentration, and optional coverage risk.
- A file with any `refactor_now` hotspot must reach at least
  `investigate_soon` in the routing queue, even when churn and coupling are
  low.
- `debt_status` is the regression verdict. `routing_pressure` is advisory.
- `signal_health=partial` is a real downgrade. The queue is still useful, but
  missing history or coverage removes part of the scoring signal.

## Change discipline

- Behavior changes still require tests.
- Structural refactors still need regression coverage to stay green.
- Keep the committed baseline under version control and refresh it only after
  debt was actually reduced or the schema changed.
- Do not raise thresholds just to match the current debt level.
