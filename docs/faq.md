# FAQ

Use this page when someone is evaluating Cremona for the first time.

## Does Cremona replace Ruff?

No.

Cremona uses Ruff C901 as one input. Keep Ruff as your normal lint pass. Use Cremona when you need a ranked refactor queue or a structural-debt gate in CI.

## Do I need coverage to use it?

No.

You can run a useful first scan without coverage:

```bash
uvx cremona scan /path/to/repo
```

Coverage improves routing confidence and risk scoring. It matters most in CI and in repositories where many risky files are under-tested.

## Do I need a baseline on day one?

No.

Run the first scan, read `report.md`, and decide whether the queue matches what the team already suspects.

Add a baseline when you want CI to fail on regressions:

```bash
uvx cremona scan /path/to/repo --update-baseline
git add quality/refactor-baseline.json
```

## Does Cremona delete dead code?

No.

`vulture` findings stay in review-only territory. A dead-code candidate is a prompt to verify call sites, framework hooks, and tests before deleting anything.

## Can Cremona scan a repository from outside that repository?

Yes.

That is the default public install path:

```bash
uvx cremona scan /path/to/repo
```

If the target repository has `[tool.cremona]` settings, Cremona uses them. Otherwise it falls back to the built-in `generic-python` profile.

## What kinds of repositories fit best?

Cremona fits best when:

- the repository is Python-only or mostly Python
- the team wants a short list of next refactor targets
- churn and coordination costs matter as much as raw complexity
- CI already exists and can produce `coverage.json`

## Can I use it with Codex or other agents?

Yes.

The repo-scoped skill and installable Codex skill are documented in [codex-skill.md](codex-skill.md). The normal loop is:

1. Run Cremona.
2. Pick the highest-pressure file.
3. Ask the agent for the smallest safe refactor.
4. Rerun Cremona.
5. Update the baseline only when debt actually dropped or the schema changed.
