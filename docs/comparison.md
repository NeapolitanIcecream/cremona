# Comparison

Use this page when you need to explain where Cremona fits in a Python quality stack.

## Short version

Cremona is narrower than a broad code-quality platform and broader than a single lint or complexity tool.

It does one job: turn Python structural-debt signals into a prioritized file queue and a CI regression gate.

## Comparison table

| Tool or workflow | What it gives you | Where it stops | Where Cremona adds value |
| --- | --- | --- | --- |
| Ruff C901 | A warning that a function is too complex | No file queue, no churn, no coupling, no baseline regression view | Cremona keeps Ruff as an input, then ranks the file against other debt signals |
| Lizard or complexipy alone | Structural metrics such as CCN, NLOC, parameter count, and cyclomatic complexity | Metrics stay separate and need manual interpretation | Cremona combines those metrics with history, dead-code findings, and optional coverage |
| Coverage alone | Which files and branches are exercised by tests | No opinion on structural pressure or refactor priority | Cremona treats low coverage as routing risk instead of a standalone score |
| Broad code-quality platforms | Multi-language dashboards, rules, and governance | Often broader than a Python team needs for refactor prioritization | Cremona stays repo-native, Python-specific, and centered on the next refactor queue |

## When Ruff is enough

Use Ruff alone when you want:

- a fast lint pass in the editor or pre-commit
- a local warning that a function crossed a complexity threshold
- broad style and correctness checks beyond refactoring decisions

## When to add Cremona

Add Cremona when you need to answer questions that Ruff cannot answer on its own:

- Which file should we refactor first?
- Did this branch make structural debt worse?
- Are we ignoring a high-churn file because each warning looks small in isolation?
- Which file should an agent touch next?

## What Cremona does not try to replace

Cremona does not replace:

- your normal linter
- your tests
- your coverage tooling
- your type checker
- a full application security or multi-language quality platform

It sits beside those tools and turns their structural signals into a queue you can act on.

## Positioning sentence

Use this sentence when you need a short description:

`Cremona turns Python structural-debt signals into a prioritized refactoring queue and CI regression gate.`
