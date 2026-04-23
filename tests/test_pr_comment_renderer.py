from __future__ import annotations

from pathlib import Path

from cremona import pr_comment
from tests._report_builders import (
    make_baseline_diff,
    make_hotspot,
    make_report,
    make_repo_verdict,
    make_routing_item,
)


def test_render_pr_comment_keeps_watch_only_summary_readable() -> None:
    report = make_report(
        repo_verdict=make_repo_verdict(
            debt_status="stable",
            routing_pressure="watch_only",
            signal_health="full",
        ),
        agent_routing_queue=[
            make_routing_item(
                file="pkg/watch.py",
                priority_band="watch",
                priority_score=12,
                change_frequency=2,
                churn=7,
                coverage={"mode": "unknown", "fraction": None},
            )
        ],
    )

    markdown = pr_comment.render_pr_comment(
        report,
        max_comment_rows=5,
        max_hotspots=3,
        artifact_name="cremona-report",
        artifact_enabled=True,
    )

    assert "- Debt status: `stable`" in markdown
    assert "- Routing pressure: `watch_only`" in markdown
    assert "### Top routing rows" in markdown
    assert "| `watch` | 12 | `pkg/watch.py` | `2 commits / 7 churn` | `unknown` |" in markdown
    assert "| `none` | - | - | - |" in markdown


def test_render_pr_comment_truncates_rows_for_corroding_report() -> None:
    report = make_report(
        repo_verdict=make_repo_verdict(
            debt_status="corroding",
            routing_pressure="investigate_now",
            signal_health="full",
        ),
        baseline_diff=make_baseline_diff(
            has_regressions=True,
            new=[{"kind": "hotspot", "file": "pkg/new.py", "symbol": "new_hotspot"}],
            worsened=[
                {"kind": "hotspot", "file": "pkg/worse.py", "symbol": "worse_hotspot"}
            ],
            resolved=[
                {"kind": "hotspot", "file": "pkg/old.py", "symbol": "old_hotspot"}
            ],
        ),
        agent_routing_queue=[
            make_routing_item(
                file="pkg/first.py",
                priority_band="investigate_now",
                priority_score=52,
                change_frequency=8,
                churn=257,
            ),
            make_routing_item(
                file="pkg/second.py",
                priority_band="investigate_soon",
                priority_score=38,
                change_frequency=6,
                churn=151,
            ),
            make_routing_item(
                file="pkg/third.py",
                priority_band="watch",
                priority_score=12,
                change_frequency=2,
                churn=14,
            ),
        ],
        hotspots=[
            make_hotspot(
                file="pkg/first.py",
                symbol="critical_one",
                classification="refactor_now",
                tools=["ruff", "lizard", "complexipy"],
                metrics={
                    "ruff": {"complexity": 26},
                    "lizard": {"ccn": 31, "nloc": 201, "parameter_count": 5},
                    "complexipy": {"complexity": 55},
                },
            ),
            make_hotspot(
                file="pkg/second.py",
                symbol="critical_two",
                classification="refactor_soon",
                tools=["ruff", "lizard"],
                metrics={
                    "ruff": {"complexity": 18},
                    "lizard": {"ccn": 22, "nloc": 140, "parameter_count": 4},
                },
            ),
        ],
    )

    markdown = pr_comment.render_pr_comment(
        report,
        max_comment_rows=2,
        max_hotspots=1,
        artifact_name="cremona-report",
        artifact_enabled=True,
    )

    assert "- Baseline regressions: `true`" in markdown
    assert "- Baseline diff: `new=1`, `worsened=1`, `resolved=1`" in markdown
    assert "`pkg/first.py`" in markdown
    assert "`pkg/second.py`" in markdown
    assert "`pkg/third.py`" not in markdown
    assert "`critical_one`" in markdown
    assert "`critical_two`" not in markdown


def test_render_pr_comment_shows_missing_signals_for_partial_health() -> None:
    report = make_report(
        repo_verdict=make_repo_verdict(
            debt_status="strained",
            routing_pressure="investigate_soon",
            signal_health="partial",
            missing_signals=["coverage", "history"],
        )
    )

    markdown = pr_comment.render_pr_comment(
        report,
        max_comment_rows=5,
        max_hotspots=3,
        artifact_name="cremona-report",
        artifact_enabled=True,
    )

    assert "- Signal health: `partial`" in markdown
    assert "- Missing signals: `coverage`, `history`" in markdown


def test_render_pr_comment_falls_back_when_report_is_missing(tmp_path: Path) -> None:
    markdown = pr_comment.render_pr_comment_from_path(
        tmp_path / "missing.json",
        max_comment_rows=5,
        max_hotspots=3,
        artifact_name="cremona-report",
        artifact_enabled=True,
    )

    assert markdown.count(pr_comment.COMMENT_MARKER) == 1
    assert "Cremona did not produce a report. See workflow logs." in markdown


def test_render_pr_comment_includes_marker_once() -> None:
    markdown = pr_comment.render_pr_comment(
        make_report(),
        max_comment_rows=5,
        max_hotspots=3,
        artifact_name="cremona-report",
        artifact_enabled=False,
    )

    assert markdown.count(pr_comment.COMMENT_MARKER) == 1


def test_reusable_gate_renders_pr_comment_without_loading_caller_project() -> None:
    workflow_path = (
        Path(__file__).resolve().parents[1]
        / ".github"
        / "workflows"
        / "reusable-gate.yml"
    )

    workflow_text = workflow_path.read_text(encoding="utf-8")

    assert "referenced_workflows" in workflow_text
    assert 'workflow_path_suffix = "/.github/workflows/reusable-gate.yml@"' in workflow_text
    assert '--with-editable "${CREMONA_RENDERER_SOURCE}" -m cremona.pr_comment' in workflow_text
    assert "uv run --isolated --no-project" in workflow_text


def test_reusable_gate_skips_stale_pr_comment_updates() -> None:
    workflow_path = (
        Path(__file__).resolve().parents[1]
        / ".github"
        / "workflows"
        / "reusable-gate.yml"
    )

    workflow_text = workflow_path.read_text(encoding="utf-8")

    assert "CREMONA_PR_HEAD_SHA" in workflow_text
    assert "Skipping stale Cremona comment update" in workflow_text
    assert "current PR head is" in workflow_text


def test_reusable_gate_selftest_grants_actions_read_for_comment_path() -> None:
    workflow_path = (
        Path(__file__).resolve().parents[1]
        / ".github"
        / "workflows"
        / "reusable-gate-selftest.yml"
    )

    workflow_text = workflow_path.read_text(encoding="utf-8")

    assert "actions: read" in workflow_text
    assert "comment-on-pr: true" in workflow_text
