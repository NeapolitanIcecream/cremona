from __future__ import annotations

from typing import Any


def _default_hotspot_summary() -> dict[str, Any]:
    return {
        "refactor_now": 0,
        "refactor_soon": 0,
        "monitor": 0,
        "multi_tool_monitor": 0,
        "top_symbols": [],
    }


def _default_routing_signals() -> dict[str, int]:
    return {
        "module_package_shadow": 0,
        "wildcard_reexport": 0,
        "facade_reexport": 0,
    }


def _default_priority_components() -> dict[str, int]:
    return {
        "change_score": 0,
        "coupling_score": 0,
        "static_score": 0,
        "subsystem_priority_score": 0,
        "routing_signal_score": 0,
        "routing_bonus_score": 0,
        "dead_code_score": 0,
        "coverage_risk_score": 0,
    }


def make_summary(**overrides: Any) -> dict[str, Any]:
    payload = {
        "files_scanned": 1,
        "hotspots_total": 0,
        "monitor_total": 0,
        "refactor_soon_total": 0,
        "refactor_now_total": 0,
        "agent_routing_queue_total": 0,
        "investigate_now_total": 0,
        "investigate_soon_total": 0,
        "watch_total": 0,
        "dead_code_candidates_total": 0,
        "dead_code_high_confidence_total": 0,
    }
    payload.update(overrides)
    return payload


def make_repo_verdict(**overrides: Any) -> dict[str, Any]:
    payload = {
        "status": "stable",
        "debt_status": "stable",
        "routing_pressure": "none",
        "summary": "No structural debt regressions were detected in the current scope.",
        "has_regressions": False,
        "signal_health": "full",
        "missing_signals": [],
        "refactor_now_total": 0,
        "investigate_now_total": 0,
        "investigate_soon_total": 0,
    }
    payload.update(overrides)
    return payload


def make_history_summary(**overrides: Any) -> dict[str, Any]:
    payload = {
        "status": "available",
        "lookback_days": 180,
        "max_commit_frequency": 0,
        "max_churn": 0,
        "files": {},
    }
    payload.update(overrides)
    return payload


def make_tool_summaries(**overrides: Any) -> dict[str, Any]:
    payload = {
        "ruff": {"findings_total": 0, "warning": 0, "high": 0, "critical": 0},
        "lizard": {"findings_total": 0, "warning": 0, "high": 0, "critical": 0},
        "complexipy": {
            "findings_total": 0,
            "warning": 0,
            "high": 0,
            "critical": 0,
        },
        "vulture": {
            "findings_total": 0,
            "review_candidate": 0,
            "high_confidence_candidate": 0,
        },
    }
    payload.update(overrides)
    return payload


def make_signal(**overrides: Any) -> dict[str, Any]:
    payload = {
        "tool": "ruff",
        "severity": "warning",
        "symbol": "branchy",
        "line": 10,
        "metrics": {"complexity": 12},
        "message": "complexity=12",
    }
    payload.update(overrides)
    return payload


def make_hotspot(**overrides: Any) -> dict[str, Any]:
    payload = {
        "id": "pkg/example.py::branchy",
        "file": "pkg/example.py",
        "symbol": "branchy",
        "classification": "monitor",
        "subsystem": "other",
        "tools": ["ruff"],
        "metrics": {"ruff": {"complexity": 12}},
        "signals": [],
    }
    payload.update(overrides)
    if "signals" not in overrides:
        payload["signals"] = [make_signal(symbol=payload["symbol"])]
    payload["tool_count"] = (
        len(payload["tools"])
        if overrides.get("tool_count") is None
        else int(overrides["tool_count"])
    )
    return payload


def make_dead_code_candidate(**overrides: Any) -> dict[str, Any]:
    payload = {
        "id": "pkg/example.py::function::unused_helper",
        "file": "pkg/example.py",
        "line": 30,
        "symbol": "unused_helper",
        "kind": "function",
        "confidence": 90,
        "classification": "high_confidence_candidate",
        "subsystem": "other",
        "size": None,
    }
    payload.update(overrides)
    return payload


def make_routing_item(**overrides: Any) -> dict[str, Any]:
    payload = {
        "file": "pkg/example.py",
        "subsystem": "other",
        "priority_score": 20,
        "priority_band": "watch",
        "change_frequency": 1,
        "churn": 2,
        "top_coupled_files": [],
        "hotspot_summary": _default_hotspot_summary(),
        "routing_signals": _default_routing_signals(),
        "routing_rules_triggered": [],
        "dead_code_candidate_count": 0,
        "coverage": {"mode": "unknown", "fraction": None},
        "priority_components": _default_priority_components(),
    }
    payload.update(overrides)
    return payload


def make_baseline_diff(**overrides: Any) -> dict[str, Any]:
    payload = {
        "baseline_available": True,
        "baseline_path": "quality/refactor-baseline.json",
        "has_regressions": False,
        "new": [],
        "worsened": [],
        "resolved": [],
    }
    payload.update(overrides)
    return payload


def make_scope(
    *,
    files: list[str] | None = None,
    file_count: int | None = None,
    **overrides: Any,
) -> dict[str, Any]:
    scope_files = files or ["pkg/example.py"]
    payload = {
        "files": scope_files,
        "file_count": len(scope_files) if file_count is None else file_count,
    }
    payload.update(overrides)
    return payload


def make_report(**overrides: Any) -> dict[str, Any]:
    payload = {
        "summary": make_summary(),
        "repo_verdict": make_repo_verdict(),
        "history_summary": make_history_summary(),
        "tool_summaries": make_tool_summaries(),
        "hotspots": [],
        "dead_code_candidates": [],
        "agent_routing_queue": [],
        "baseline_diff": make_baseline_diff(),
        "recommended_queue": [],
        "recommended_refactor_queue": [],
        "scope": make_scope(),
        "schema_version": 3,
        "generated_at": "2026-04-02T00:00:00+00:00",
    }
    payload.update(overrides)
    return payload
