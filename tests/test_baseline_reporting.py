from __future__ import annotations

from pathlib import Path
from typing import Any

import cremona.scan as audit
from tests._report_builders import (
    make_baseline_diff,
    make_dead_code_candidate,
    make_history_summary,
    make_hotspot,
    make_report,
    make_repo_verdict,
    make_routing_item,
    make_scope,
    make_signal,
    make_summary,
    make_tool_summaries,
)

CONFIG = audit.load_audit_config(repo_root=Path(__file__).resolve().parents[1])
audit._set_active_profile(audit.get_profile("generic-python"))



def _partial_scope_baseline_report() -> dict[str, Any]:
    return {
        "schema_version": 3,
        "scope": make_scope(
            files=["pkg/in_scope.py", "pkg/out_of_scope.py"],
            file_count=2,
        ),
        "hotspots": [
            make_hotspot(
                id="pkg/in_scope.py::branchy",
                file="pkg/in_scope.py",
                classification="monitor",
                metrics={"ruff": {"complexity": 12}},
                signals=[
                    make_signal(
                        tool="ruff",
                        severity="warning",
                        symbol="branchy",
                        metrics={"complexity": 12},
                    )
                ],
            ),
            make_hotspot(
                id="pkg/out_of_scope.py::other_hotspot",
                file="pkg/out_of_scope.py",
                symbol="other_hotspot",
                classification="refactor_now",
                tools=["complexipy"],
                metrics={"complexipy": {"complexity": 55}},
                signals=[
                    make_signal(
                        tool="complexipy",
                        severity="critical",
                        symbol="other_hotspot",
                        line=20,
                        metrics={"complexity": 55},
                        message="complexity=55",
                    )
                ],
            ),
        ],
        "dead_code_candidates": [
            make_dead_code_candidate(
                id="pkg/out_of_scope.py::function::unused_helper",
                file="pkg/out_of_scope.py",
            )
        ],
        "agent_routing_queue": [
            make_routing_item(
                file="pkg/out_of_scope.py",
                priority_score=80,
                priority_band="investigate_now",
                change_frequency=8,
                churn=100,
                dead_code_candidate_count=1,
                hotspot_summary={
                    "refactor_now": 1,
                    "refactor_soon": 0,
                    "monitor": 0,
                    "multi_tool_monitor": 0,
                    "top_symbols": [],
                },
                priority_components={
                    "change_score": 10,
                    "coupling_score": 0,
                    "static_score": 5,
                    "subsystem_priority_score": 0,
                    "routing_signal_score": 0,
                    "routing_bonus_score": 0,
                    "dead_code_score": 3,
                    "coverage_risk_score": 0,
                },
            )
        ],
        "history_summary": make_history_summary(
            max_commit_frequency=8,
            max_churn=100,
            files={
                "pkg/out_of_scope.py": {
                    "commit_frequency": 8,
                    "churn": 100,
                    "top_coupled_files": [],
                }
            },
        ),
    }



def _partial_scope_current_report() -> dict[str, Any]:
    return make_report(
        summary=make_summary(
            files_scanned=1,
            hotspots_total=1,
            refactor_soon_total=1,
            agent_routing_queue_total=1,
            investigate_soon_total=1,
        ),
        repo_verdict=make_repo_verdict(
            status="strained",
            debt_status="strained",
            routing_pressure="investigate_soon",
            summary=(
                "Existing structural debt remains, but the current scope did not regress. "
                "Routing pressure is investigate_soon. Signal health is partial: missing coverage."
            ),
            signal_health="partial",
            missing_signals=["coverage"],
            investigate_soon_total=1,
        ),
        hotspots=[
            make_hotspot(
                id="pkg/in_scope.py::branchy",
                file="pkg/in_scope.py",
                classification="refactor_soon",
                metrics={"ruff": {"complexity": 26}},
                signals=[
                    make_signal(
                        tool="ruff",
                        severity="critical",
                        symbol="branchy",
                        metrics={"complexity": 26},
                        message="complexity=26",
                    )
                ],
            )
        ],
        tool_summaries=make_tool_summaries(
            ruff={"findings_total": 1, "warning": 0, "high": 0, "critical": 1},
        ),
        baseline_diff=make_baseline_diff(
            has_regressions=True,
            new=[{"kind": "hotspot"}],
        ),
        agent_routing_queue=[
            make_routing_item(
                file="pkg/in_scope.py",
                priority_score=50,
                priority_band="investigate_soon",
                change_frequency=5,
                churn=40,
                coverage={"mode": "line", "fraction": 0.5},
                hotspot_summary={
                    "refactor_now": 0,
                    "refactor_soon": 1,
                    "monitor": 0,
                    "multi_tool_monitor": 0,
                    "top_symbols": [],
                },
                priority_components={
                    "change_score": 10,
                    "coupling_score": 0,
                    "static_score": 3,
                    "subsystem_priority_score": 0,
                    "routing_signal_score": 0,
                    "routing_bonus_score": 0,
                    "dead_code_score": 0,
                    "coverage_risk_score": 5,
                },
            )
        ],
        history_summary=make_history_summary(
            max_commit_frequency=5,
            max_churn=40,
            files={
                "pkg/in_scope.py": {
                    "commit_frequency": 5,
                    "churn": 40,
                    "top_coupled_files": [],
                }
            },
        ),
        scope=make_scope(files=["pkg/in_scope.py"], file_count=1),
    )



def _partial_scope_snapshot_inputs() -> tuple[dict[str, Any], dict[str, Any]]:
    return (_partial_scope_baseline_report(), _partial_scope_current_report())



def test_build_baseline_diff_marks_new_hotspots() -> None:
    current_hotspots = [
        {
            "id": "pkg/example.py::branchy",
            "file": "pkg/example.py",
            "symbol": "branchy",
            "classification": "refactor_soon",
            "tools": ["ruff"],
            "metrics": {"ruff": {"complexity": 16}},
        }
    ]

    diff = audit.build_baseline_diff(
        current_hotspots=current_hotspots,
        current_dead_code_candidates=[],
        baseline_report={
            "schema_version": 3,
            "hotspots": [],
            "dead_code_candidates": [],
        },
        scope_files=["pkg/example.py"],
        config=CONFIG,
    )

    assert diff["new"][0]["kind"] == "hotspot"
    assert diff["new"][0]["symbol"] == "branchy"



def test_build_baseline_diff_marks_worsened_hotspots() -> None:
    baseline_report = {
        "schema_version": 3,
        "hotspots": [
            {
                "id": "pkg/example.py::branchy",
                "file": "pkg/example.py",
                "symbol": "branchy",
                "classification": "monitor",
                "tools": ["ruff"],
                "metrics": {"ruff": {"complexity": 12}},
            }
        ],
        "dead_code_candidates": [],
    }
    current_hotspots = [
        {
            "id": "pkg/example.py::branchy",
            "file": "pkg/example.py",
            "symbol": "branchy",
            "classification": "refactor_soon",
            "tools": ["ruff", "lizard"],
            "metrics": {
                "ruff": {"complexity": 16},
                "lizard": {"ccn": 18, "nloc": 90, "parameter_count": 4},
            },
        }
    ]

    diff = audit.build_baseline_diff(
        current_hotspots=current_hotspots,
        current_dead_code_candidates=[],
        baseline_report=baseline_report,
        scope_files=["pkg/example.py"],
        config=CONFIG,
    )

    assert diff["worsened"][0]["kind"] == "hotspot"
    assert "classification" in diff["worsened"][0]["reasons"]



def test_build_baseline_diff_ignores_same_band_lizard_nloc_growth() -> None:
    baseline_report = {
        "schema_version": 3,
        "hotspots": [
            {
                "id": "pkg/example.py::branchy",
                "file": "pkg/example.py",
                "symbol": "branchy",
                "classification": "monitor",
                "tools": ["lizard"],
                "metrics": {"lizard": {"ccn": 10, "nloc": 117, "parameter_count": 4}},
            }
        ],
        "dead_code_candidates": [],
    }
    current_hotspots = [
        {
            "id": "pkg/example.py::branchy",
            "file": "pkg/example.py",
            "symbol": "branchy",
            "classification": "monitor",
            "tools": ["lizard"],
            "metrics": {"lizard": {"ccn": 10, "nloc": 125, "parameter_count": 4}},
        }
    ]

    diff = audit.build_baseline_diff(
        current_hotspots=current_hotspots,
        current_dead_code_candidates=[],
        baseline_report=baseline_report,
        scope_files=["pkg/example.py"],
        config=CONFIG,
    )

    assert diff["has_regressions"] is False
    assert diff["worsened"] == []



def test_build_baseline_diff_ignores_new_monitor_lizard_nloc_hotspot() -> None:
    current_hotspots = [
        {
            "id": "pkg/example.py::wrapped",
            "file": "pkg/example.py",
            "symbol": "wrapped",
            "classification": "monitor",
            "tools": ["lizard"],
            "metrics": {"lizard": {"ccn": 8, "nloc": 102, "parameter_count": 3}},
        }
    ]

    diff = audit.build_baseline_diff(
        current_hotspots=current_hotspots,
        current_dead_code_candidates=[],
        baseline_report={
            "schema_version": 3,
            "hotspots": [],
            "dead_code_candidates": [],
        },
        scope_files=["pkg/example.py"],
        config=CONFIG,
    )

    assert diff["has_regressions"] is False
    assert diff["new"] == []



def test_build_baseline_diff_marks_resolved_hotspots() -> None:
    baseline_report = {
        "schema_version": 3,
        "hotspots": [
            {
                "id": "pkg/example.py::branchy",
                "file": "pkg/example.py",
                "symbol": "branchy",
                "classification": "refactor_soon",
                "tools": ["ruff"],
                "metrics": {"ruff": {"complexity": 16}},
            }
        ],
        "dead_code_candidates": [],
    }

    diff = audit.build_baseline_diff(
        current_hotspots=[],
        current_dead_code_candidates=[],
        baseline_report=baseline_report,
        scope_files=["pkg/example.py"],
        config=CONFIG,
    )

    assert diff["resolved"][0]["kind"] == "hotspot"
    assert diff["resolved"][0]["symbol"] == "branchy"



def test_render_markdown_report_contains_required_sections() -> None:
    report = make_report(
        summary=make_summary(
            files_scanned=1,
            hotspots_total=1,
            refactor_soon_total=1,
            agent_routing_queue_total=1,
            investigate_soon_total=1,
            dead_code_candidates_total=1,
            dead_code_high_confidence_total=1,
        ),
        repo_verdict=make_repo_verdict(
            status="strained",
            debt_status="strained",
            routing_pressure="investigate_soon",
            summary=(
                "Existing structural debt remains, but the current scope did not regress. "
                "Routing pressure is investigate_soon. Signal health is partial: missing coverage."
            ),
            signal_health="partial",
            missing_signals=["coverage"],
        ),
        tool_summaries=make_tool_summaries(
            ruff={"findings_total": 1, "warning": 1, "high": 0, "critical": 0},
            lizard={"findings_total": 1, "warning": 1, "high": 0, "critical": 0},
            vulture={
                "findings_total": 1,
                "review_candidate": 0,
                "high_confidence_candidate": 1,
            },
        ),
        hotspots=[
            make_hotspot(
                classification="refactor_soon",
                tools=["lizard", "ruff"],
                metrics={
                    "lizard": {"ccn": 18, "nloc": 90, "parameter_count": 4},
                    "ruff": {"complexity": 16},
                },
            )
        ],
        dead_code_candidates=[make_dead_code_candidate()],
        agent_routing_queue=[
            make_routing_item(
                priority_score=40,
                priority_band="investigate_soon",
                change_frequency=4,
                churn=20,
                coverage={"mode": "branch", "fraction": 0.8},
            )
        ],
        baseline_diff=make_baseline_diff(),
        recommended_refactor_queue=[
            {"subsystem": "pipeline", "investigate_now": 0, "investigate_soon": 0, "watch": 0},
            {"subsystem": "other", "investigate_now": 0, "investigate_soon": 1, "watch": 0},
        ],
    )

    markdown = audit.render_markdown_report(report)

    assert "Repo verdict" in markdown
    assert "Debt status" in markdown
    assert "Routing pressure" in markdown
    assert "Signal health" in markdown
    assert "Missing signals: coverage" in markdown
    assert "Agent routing queue" in markdown
    assert "Top hotspots" in markdown
    assert "Dead code candidates" in markdown
    assert "Recommended refactor queue" in markdown



def test_build_baseline_snapshot_resets_diff_and_repo_verdict() -> None:
    report = make_report(
        summary=make_summary(files_scanned=1, hotspots_total=1, refactor_soon_total=1),
        repo_verdict=make_repo_verdict(
            status="corroding",
            debt_status="corroding",
            summary="Structural debt is regressing in the current scope.",
            has_regressions=True,
        ),
        hotspots=[
            make_hotspot(
                classification="refactor_soon",
                metrics={"ruff": {"complexity": 16}},
            )
        ],
        baseline_diff=make_baseline_diff(
            has_regressions=True,
            new=[{"kind": "hotspot"}],
        ),
    )

    snapshot = audit.build_baseline_snapshot(report)

    assert snapshot["baseline_diff"]["baseline_available"] is False
    assert snapshot["baseline_diff"]["has_regressions"] is False
    assert snapshot["baseline_diff"]["new"] == []
    assert snapshot["history_summary"]["status"] == "available"
    assert snapshot["agent_routing_queue"] == []
    assert snapshot["repo_verdict"]["status"] == "strained"



def test_build_baseline_snapshot_preserves_out_of_scope_records() -> None:
    baseline_report, report = _partial_scope_snapshot_inputs()
    snapshot = audit.build_baseline_snapshot(
        report,
        baseline_report=baseline_report,
        scope_files=["pkg/in_scope.py"],
    )

    assert [item["id"] for item in snapshot["hotspots"]] == [
        "pkg/out_of_scope.py::other_hotspot",
        "pkg/in_scope.py::branchy",
    ]
    assert snapshot["dead_code_candidates"][0]["file"] == "pkg/out_of_scope.py"
    assert [item["file"] for item in snapshot["agent_routing_queue"]] == [
        "pkg/out_of_scope.py",
        "pkg/in_scope.py",
    ]
    assert snapshot["history_summary"]["files"]["pkg/out_of_scope.py"]["churn"] == 100



def test_build_baseline_snapshot_recomputes_summary_and_tool_summaries_after_partial_merge() -> None:
    baseline_report, report = _partial_scope_snapshot_inputs()
    snapshot = audit.build_baseline_snapshot(
        report,
        baseline_report=baseline_report,
        scope_files=["pkg/in_scope.py"],
    )

    assert snapshot["summary"]["files_scanned"] == 2
    assert snapshot["summary"]["hotspots_total"] == 2
    assert snapshot["tool_summaries"]["ruff"]["critical"] == 1
    assert snapshot["tool_summaries"]["complexipy"]["critical"] == 1
    assert snapshot["baseline_diff"]["has_regressions"] is False



def test_build_baseline_snapshot_rebuilds_recommended_queue_after_partial_merge() -> None:
    baseline_report, report = _partial_scope_snapshot_inputs()
    snapshot = audit.build_baseline_snapshot(
        report,
        baseline_report=baseline_report,
        scope_files=["pkg/in_scope.py"],
    )

    recommended_other = next(
        item for item in snapshot["recommended_queue"] if item["subsystem"] == "other"
    )
    assert recommended_other["investigate_now"] == 1
    assert recommended_other["investigate_soon"] == 1
    assert snapshot["recommended_queue"] == snapshot["recommended_refactor_queue"]



def test_build_baseline_snapshot_recomputes_history_extrema_after_partial_merge() -> None:
    baseline_report, report = _partial_scope_snapshot_inputs()
    snapshot = audit.build_baseline_snapshot(
        report,
        baseline_report=baseline_report,
        scope_files=["pkg/in_scope.py"],
    )

    assert snapshot["history_summary"]["max_commit_frequency"] == 8
    assert snapshot["history_summary"]["max_churn"] == 100



def test_build_baseline_snapshot_rejects_legacy_baseline_schema() -> None:
    baseline_report = {
        "schema_version": 2,
        "scope": make_scope(
            files=["pkg/in_scope.py", "pkg/out_of_scope.py"],
            file_count=2,
        ),
        "hotspots": [],
        "dead_code_candidates": [],
    }
    report = make_report(
        summary=make_summary(
            files_scanned=1,
            agent_routing_queue_total=1,
            watch_total=1,
        ),
        agent_routing_queue=[
            make_routing_item(
                file="pkg/in_scope.py",
                subsystem="other",
                priority_score=20,
                priority_band="watch",
                change_frequency=1,
                churn=2,
            )
        ],
        history_summary=make_history_summary(
            max_commit_frequency=1,
            max_churn=2,
            files={
                "pkg/in_scope.py": {
                    "commit_frequency": 1,
                    "churn": 2,
                    "top_coupled_files": [],
                }
            },
        ),
        baseline_diff=make_baseline_diff(),
        scope=make_scope(files=["pkg/in_scope.py"], file_count=1),
    )

    try:
        audit.build_baseline_snapshot(
            report,
            baseline_report=baseline_report,
            scope_files=["pkg/in_scope.py"],
        )
    except RuntimeError as exc:
        message = str(exc)
    else:
        raise AssertionError("Expected legacy baseline schema to be rejected")

    assert "schema version" in message
    assert "Regenerate the baseline" in message
