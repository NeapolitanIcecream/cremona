# Case study: Typer

Use this page when you want to see what a first external scan looks like on a real open-source Python repository.

## Scope

- Repository: [`fastapi/typer`](https://github.com/fastapi/typer)
- Scan date: April 22, 2026
- Repository snapshot: commit `2046219`
- Command:

```bash
uv run cremona scan /tmp/typer --out-dir /tmp/typer-cremona
```

This was a quick audit without coverage input, so `signal_health` is `partial`.

## Repo verdict

- `debt_status`: `strained`
- `routing_pressure`: `investigate_now`
- `signal_health`: `partial`
- Missing signals: `coverage`
- Files scanned: `600`
- Hotspots: `37`
- Queue rows: `600`

The important part is the mix of results. Typer does not look like a repository in immediate regression, but it does have a clear group of files where structural pressure, churn, and coupling overlap.

## Top queue rows

| File | Priority | Why it ranked highly |
| --- | --- | --- |
| `typer/main.py` | `investigate_now` | `10` commits and `1313` churn in the last `180` days, plus multiple `refactor_now` hotspots in parameter and type resolution code |
| `typer/core.py` | `investigate_soon` | `8` commits, active coupling with markup-related tests, and high-pressure help rendering paths |
| `typer/rich_utils.py` | `investigate_soon` | multiple `refactor_now` hotspots in rich help formatting, plus recent churn |
| `typer/params.py` | `investigate_soon` | very high churn relative to recent commit count and tight coupling with `typer/main.py` and `typer/models.py` |
| `typer/models.py` | `investigate_soon` | lower change count than `main.py`, but still coupled to parameter handling and carrying a very large initializer surface |

## Hotspots that explain the queue

These symbol-level hotspots do most of the explaining:

| Symbol | File | Why it matters |
| --- | --- | --- |
| `get_click_param` | `typer/main.py` | `complexipy=40`, `lizard CCN=22`, `NLOC=145`, `ruff complexity=21` |
| `get_click_type` | `typer/main.py` | `complexipy=32`, `lizard CCN=30`, `NLOC=94`, `ruff complexity=20` |
| `get_docs_for_click` | `typer/cli.py` | three-tool agreement with high structural pressure in docs extraction |
| `TyperOption::get_help_record` | `typer/core.py` | three-tool agreement in help rendering code that likely sees frequent UX-driven edits |
| `rich_format_help` | `typer/rich_utils.py` | high structural pressure in output formatting logic, with neighboring rich helpers also flagged |

## What this suggests

If this were a real adoption pass, the safest next sequence would be:

1. Start with `typer/main.py`, because it is the only `investigate_now` file and it concentrates both churn and hotspot pressure.
2. Follow with `typer/core.py` and `typer/rich_utils.py`, because they form a cluster around help and parameter rendering.
3. Use `typer/params.py` and `typer/models.py` as the second wave, after the `main.py` call path is better isolated.

## Caveats

- No `coverage.json` was provided, so coverage risk stayed `unknown`.
- No baseline was available, so this was a prioritization pass, not a regression decision.
- High-confidence dead-code candidates appeared in docs and tests as well as runtime modules. They should still be reviewed, not deleted automatically.

## Why this case study matters

The useful part is not the raw count of hotspots. The useful part is that Cremona narrows hundreds of Python files into one file to open now, a small group to plan next, and a larger background queue to monitor.
