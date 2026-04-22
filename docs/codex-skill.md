# Codex skill

Use Cremona's bundled Codex skill when you want an agent to move from scan output to a concrete refactor plan.

## Repo-scoped skill

When you start Codex inside this repository, it discovers the skill at:

`.agents/skills/cremona-proactive-refactor-audit`

Invoke it with:

```text
$cremona-proactive-refactor-audit
```

## Install it in your personal Codex setup

Use the built-in skill installer and point it at this repository:

```text
$skill-installer install the skill from https://github.com/NeapolitanIcecream/cremona/tree/main/.agents/skills/cremona-proactive-refactor-audit
```

Restart Codex if the skill does not appear immediately.

## Recommended workflow

Use this loop:

1. `uvx cremona scan /path/to/repo`
2. Open `report.md`
3. Choose the top file from `agent_routing_queue`
4. Ask Codex for the smallest safe refactor on that file
5. Rerun Cremona
6. Update the baseline only when debt actually dropped or the schema changed

## What the skill does

The skill helps Codex:

- locate a Cremona checkout or executable
- run a full-repo or narrowed scan
- read `report.md` before `report.json`
- summarize the repo verdict
- rank the next refactor targets with evidence
- keep dead-code findings in review-only territory

## When to use it

Use the skill when you want answers like:

- What should we refactor next?
- Did this branch make structural debt worse?
- Which file should an agent touch first?
- Should we refresh the baseline or fix the regression?
