# Methodology

Use Cremona when you need a low-ambiguity answer to two questions:

1. Is the repository accumulating structural debt?
2. What should be refactored next?

## Workflow

1. Run `ruff` first to confirm the normal lint baseline.
2. Run `cremona scan` on the whole repository, or narrow the scope to the files
   you are actively changing.
3. Pass `--coverage-json` when coverage data exists.
4. Read `report.md` first for the repo verdict and routing queue.
5. Read `report.json` when you need symbol-level evidence or baseline details.

## Interpretation rules

- `ruff` C901 is the early warning signal for control-flow growth.
- `lizard` measures structural pressure through `CCN`, `NLOC`, and parameter
  count.
- `complexipy` is the main signal for "hard to change safely."
- `vulture` only produces review candidates. It is not permission to delete
  code automatically.
- The file-level routing queue is the main prioritization view. It combines
  static pressure, change frequency, churn, coupling, ambiguity signals,
  dead-code concentration, and optional coverage risk.
- `debt_status` is the regression verdict. `routing_pressure` is advisory.
- `signal_health=partial` is a real downgrade. The queue is still useful, but
  missing history or coverage removes part of the scoring signal.

## Change discipline

- Behavior changes still require tests.
- Structural refactors still need regression coverage to stay green.
- Do not raise thresholds just to match the current debt level.
- Update a baseline only after debt was genuinely reduced or the old baseline
  schema became obsolete.
