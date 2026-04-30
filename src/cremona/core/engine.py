from __future__ import annotations

import argparse
import json
import os
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from ..profiles import Profile, get_profile
from ..python_tools.engine import (
    ScopeLookup,
    collect_python_files,
    dead_code_sort_key,
    optional_int,
    parse_complexipy_findings,
    parse_lizard_findings,
    parse_ruff_findings,
    parse_vulture_candidates,
    relative_path,
    run_command,
)
from . import routing as _routing
from .config import load_audit_config
from .history import (
    _GitHistoryCollectionRequest,
    build_history_summary as build_history_summary,
    collect_git_history_summary as _collect_git_history_summary,
)
from .models import (
    HOTSPOT_CLASSIFICATION_RANK,
    SCHEMA_VERSION,
    SEVERITY_RANK,
    AuditConfig,
    AuditScopeState,
    AuditToolRunResult,
    HotspotSignal,
    RefactorAuditRunRequest,
    ScanReport,
    ScanRequest,
    _AuditReportContext,
    _DiffRegressionContext,
)
from .routing import (
    _routing_pressure,
    _unknown_coverage_summary,
    agent_routing_sort_key,
    build_agent_routing_index,
    build_agent_routing_queue,
    build_recommended_queue,
    hotspot_sort_key,
    infer_subsystem,
)

DEFAULT_PROFILE = _routing.DEFAULT_PROFILE
empty_routing_signals = _routing.empty_routing_signals
QUEUE_ORDER = _routing.QUEUE_ORDER
_ACTIVE_PROFILE = _routing.get_active_profile()


@dataclass(frozen=True)
class _AuditExecutionResult:
    report: dict[str, Any]
    baseline_report: dict[str, Any] | None
    baseline_diff: dict[str, Any]


def _set_active_profile(profile: Profile) -> Profile:
    global _ACTIVE_PROFILE
    global QUEUE_ORDER
    previous = _routing.set_active_profile(profile)
    _ACTIVE_PROFILE = _routing.get_active_profile()
    QUEUE_ORDER = _routing.QUEUE_ORDER
    return previous


def collect_git_history_summary(
    request: _GitHistoryCollectionRequest | None = None,
    **legacy_kwargs: Any,
) -> dict[str, Any]:
    return _collect_git_history_summary(
        request=request,
        command_runner=run_command,
        **legacy_kwargs,
    )


def _has_critical_complexity_signal(
    values: list[HotspotSignal],
    *,
    config: AuditConfig,
) -> bool:
    for signal in values:
        if signal.tool == "complexipy" and signal.severity == "critical":
            return True
        if signal.tool != "lizard":
            continue
        ccn = int(signal.metrics.get("ccn", 0))
        if config.lizard.ccn.classify(ccn) == "critical":
            return True
    return False


def _classify_hotspot(values: list[HotspotSignal], *, config: AuditConfig) -> str:
    distinct_warning_plus = {
        signal.tool for signal in values if SEVERITY_RANK[signal.severity] >= 1
    }
    distinct_high_plus = {
        signal.tool for signal in values if SEVERITY_RANK[signal.severity] >= 2
    }
    has_critical_complexity = _has_critical_complexity_signal(
        values,
        config=config,
    )
    if has_critical_complexity or len(distinct_high_plus) >= 2:
        return "refactor_now"
    if (
        any(signal.severity in {"high", "critical"} for signal in values)
        or len(distinct_warning_plus) >= 3
    ):
        return "refactor_soon"
    return "monitor"


def _hotspot_metrics_by_tool(values: list[HotspotSignal]) -> dict[str, dict[str, int]]:
    metrics_by_tool: dict[str, dict[str, int]] = {}
    for signal in values:
        existing = metrics_by_tool.setdefault(signal.tool, {})
        for key, value in signal.metrics.items():
            existing[key] = max(existing.get(key, value), value)
    return metrics_by_tool


def _hotspot_signal_payload(values: list[HotspotSignal]) -> list[dict[str, Any]]:
    return [
        {
            "tool": signal.tool,
            "severity": signal.severity,
            "symbol": signal.symbol,
            "line": signal.line,
            "metrics": signal.metrics,
            "message": signal.message,
        }
        for signal in sorted(
            values,
            key=lambda item: (
                -SEVERITY_RANK[item.severity],
                item.tool,
                item.symbol,
            ),
        )
    ]


def _aggregate_hotspot_record(
    *,
    hotspot_id: str,
    values: list[HotspotSignal],
    config: AuditConfig,
) -> dict[str, Any]:
    line_candidates = [signal.line for signal in values if signal.line is not None]
    return {
        "id": hotspot_id,
        "file": values[0].file,
        "symbol": max((signal.symbol for signal in values), key=len),
        "line": min(line_candidates) if line_candidates else None,
        "classification": _classify_hotspot(values, config=config),
        "subsystem": infer_subsystem(values[0].file),
        "tool_count": len({signal.tool for signal in values}),
        "tools": sorted({signal.tool for signal in values}),
        "metrics": _hotspot_metrics_by_tool(values),
        "signals": _hotspot_signal_payload(values),
    }


def aggregate_hotspots(
    signals: list[HotspotSignal],
    *,
    config: AuditConfig,
) -> list[dict[str, Any]]:
    grouped: dict[str, list[HotspotSignal]] = defaultdict(list)
    for signal in signals:
        grouped[signal.symbol_key].append(signal)

    hotspots = [
        _aggregate_hotspot_record(
            hotspot_id=hotspot_id,
            values=values,
            config=config,
        )
        for hotspot_id, values in grouped.items()
    ]
    hotspots.sort(key=hotspot_sort_key)
    return hotspots


def build_tool_summaries(
    *,
    ruff_signals: list[HotspotSignal],
    lizard_signals: list[HotspotSignal],
    complexipy_signals: list[HotspotSignal],
    dead_code_candidates: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    return {
        "ruff": severity_summary(ruff_signals),
        "lizard": severity_summary(lizard_signals),
        "complexipy": severity_summary(complexipy_signals),
        "vulture": {
            "findings_total": len(dead_code_candidates),
            "review_candidate": sum(
                1
                for candidate in dead_code_candidates
                if candidate["classification"] == "review_candidate"
            ),
            "high_confidence_candidate": sum(
                1
                for candidate in dead_code_candidates
                if candidate["classification"] == "high_confidence_candidate"
            ),
        },
    }


def severity_summary(signals: list[HotspotSignal]) -> dict[str, int]:
    counter = Counter(signal.severity for signal in signals)
    return {
        "findings_total": len(signals),
        "warning": int(counter.get("warning", 0)),
        "high": int(counter.get("high", 0)),
        "critical": int(counter.get("critical", 0)),
    }


def severity_summary_from_levels(levels: Iterable[str]) -> dict[str, int]:
    counter = Counter(level for level in levels if level in SEVERITY_RANK)
    return {
        "findings_total": sum(counter.values()),
        "warning": int(counter.get("warning", 0)),
        "high": int(counter.get("high", 0)),
        "critical": int(counter.get("critical", 0)),
    }


def build_tool_summaries_from_snapshot(
    *, hotspots: list[dict[str, Any]], dead_code_candidates: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    severities_by_tool: dict[str, list[str]] = {
        "ruff": [],
        "lizard": [],
        "complexipy": [],
    }
    for hotspot in hotspots:
        for signal in hotspot.get("signals", []):
            tool = signal.get("tool")
            severity = signal.get("severity")
            if tool in severities_by_tool and isinstance(severity, str):
                severities_by_tool[tool].append(severity)

    return {
        "ruff": severity_summary_from_levels(severities_by_tool["ruff"]),
        "lizard": severity_summary_from_levels(severities_by_tool["lizard"]),
        "complexipy": severity_summary_from_levels(severities_by_tool["complexipy"]),
        "vulture": {
            "findings_total": len(dead_code_candidates),
            "review_candidate": sum(
                1
                for candidate in dead_code_candidates
                if candidate["classification"] == "review_candidate"
            ),
            "high_confidence_candidate": sum(
                1
                for candidate in dead_code_candidates
                if candidate["classification"] == "high_confidence_candidate"
            ),
        },
    }


def _initial_coverage_files(tracked_files: Iterable[str]) -> dict[str, dict[str, Any]]:
    return {
        file_name: _unknown_coverage_summary() for file_name in sorted(set(tracked_files))
    }


def _load_coverage_files_payload(coverage_json: Path | None) -> dict[str, Any] | None:
    if coverage_json is None or not coverage_json.exists():
        return None
    payload = json.loads(coverage_json.read_text(encoding="utf-8"))
    coverage_files = payload.get("files", {})
    return coverage_files if isinstance(coverage_files, dict) else None


def _resolve_coverage_entry(
    *,
    file_name: str,
    repo_root: Path,
    coverage_files: Mapping[str, Any],
) -> dict[str, Any] | None:
    for candidate in (file_name, str((repo_root / file_name).resolve())):
        entry = coverage_files.get(candidate)
        if isinstance(entry, dict):
            return entry
    return None


def _coverage_summary_from_entry(entry: dict[str, Any]) -> dict[str, Any] | None:
    summary = entry.get("summary", {})
    if not isinstance(summary, dict):
        return None
    covered_branches = optional_int(summary.get("covered_branches"))
    num_branches = optional_int(summary.get("num_branches"))
    if covered_branches is not None and num_branches is not None and num_branches > 0:
        return {
            "mode": "branch",
            "fraction": round(covered_branches / num_branches, 4),
        }
    covered_lines = optional_int(summary.get("covered_lines"))
    num_statements = optional_int(summary.get("num_statements"))
    if covered_lines is not None and num_statements is not None and num_statements > 0:
        return {
            "mode": "line",
            "fraction": round(covered_lines / num_statements, 4),
        }
    return None


def load_coverage_summary(
    *,
    coverage_json: Path | None,
    repo_root: Path,
    tracked_files: Iterable[str],
) -> dict[str, Any]:
    tracked_file_set = set(tracked_files)
    files = _initial_coverage_files(tracked_file_set)
    coverage_files = _load_coverage_files_payload(coverage_json)
    if coverage_files is None:
        return {
            "status": "unavailable",
            "files": files,
        }
    for file_name in sorted(tracked_file_set):
        entry = _resolve_coverage_entry(
            file_name=file_name,
            repo_root=repo_root,
            coverage_files=coverage_files,
        )
        if entry is None:
            continue
        summary = _coverage_summary_from_entry(entry)
        if summary is None:
            continue
        files[file_name] = summary
    return {
        "status": "available",
        "files": files,
    }

def _missing_signals(
    *,
    history_summary: dict[str, Any] | None,
    agent_routing_queue: list[dict[str, Any]],
) -> list[str]:
    missing: list[str] = []
    if history_summary is not None and history_summary.get("status") != "available":
        missing.append("git_history")
    if agent_routing_queue and not all(
        item.get("coverage", {}).get("mode") in {"branch", "line"}
        for item in agent_routing_queue
    ):
        missing.append("coverage")
    return missing


def _signal_health(
    *,
    history_summary: dict[str, Any] | None,
    agent_routing_queue: list[dict[str, Any]],
) -> tuple[str, list[str]]:
    missing_signals = _missing_signals(
        history_summary=history_summary,
        agent_routing_queue=agent_routing_queue,
    )
    if not missing_signals:
        return ("full", [])
    if len(missing_signals) >= 2:
        return ("minimal", missing_signals)
    return ("partial", missing_signals)


def build_baseline_diff(
    *,
    current_hotspots: list[dict[str, Any]],
    current_dead_code_candidates: list[dict[str, Any]],
    baseline_report: dict[str, Any] | None,
    scope_files: list[str],
    config: AuditConfig,
) -> dict[str, Any]:
    scoped_files = set(scope_files)
    if baseline_report is None:
        return _empty_baseline_diff()
    _require_supported_baseline_report(baseline_report)

    baseline_hotspots = _baseline_items_by_id(
        baseline_report=baseline_report,
        key="hotspots",
        scoped_files=scoped_files,
    )
    current_hotspots_by_id = {item["id"]: item for item in current_hotspots}
    baseline_dead_code = _baseline_items_by_id(
        baseline_report=baseline_report,
        key="dead_code_candidates",
        scoped_files=scoped_files,
    )
    current_dead_code_by_id = {
        item["id"]: item for item in current_dead_code_candidates
    }

    diff_items = {"new": [], "worsened": [], "resolved": []}
    _collect_item_regressions(
        diff_items=diff_items,
        context=_DiffRegressionContext(
            current_items_by_id=current_hotspots_by_id,
            baseline_items_by_id=baseline_hotspots,
            kind="hotspot",
            summarize=summarize_hotspot,
            new_item_is_regression=lambda item: hotspot_new_item_is_regression(
                item,
                config=config,
            ),
            regression_reasons=lambda previous, item: hotspot_regression_reasons(
                previous,
                item,
                config=config,
            ),
        ),
    )
    _collect_resolved_items(
        diff_items=diff_items,
        current_items_by_id=current_hotspots_by_id,
        baseline_items_by_id=baseline_hotspots,
        kind="hotspot",
        summarize=summarize_hotspot,
    )
    _collect_item_regressions(
        diff_items=diff_items,
        context=_DiffRegressionContext(
            current_items_by_id=current_dead_code_by_id,
            baseline_items_by_id=baseline_dead_code,
            kind="dead_code",
            summarize=summarize_dead_code,
            new_item_is_regression=lambda _item: True,
            regression_reasons=dead_code_regression_reasons,
        ),
    )
    _collect_resolved_items(
        diff_items=diff_items,
        current_items_by_id=current_dead_code_by_id,
        baseline_items_by_id=baseline_dead_code,
        kind="dead_code",
        summarize=summarize_dead_code,
    )
    _sort_diff_items(diff_items)

    return {
        "baseline_available": True,
        "baseline_path": baseline_report.get("_baseline_path"),
        "has_regressions": bool(diff_items["new"] or diff_items["worsened"]),
        "new": diff_items["new"],
        "worsened": diff_items["worsened"],
        "resolved": diff_items["resolved"],
    }


def _empty_baseline_diff() -> dict[str, Any]:
    return {
        "baseline_available": False,
        "baseline_path": None,
        "has_regressions": False,
        "new": [],
        "worsened": [],
        "resolved": [],
    }


def _baseline_items_by_id(
    *,
    baseline_report: dict[str, Any],
    key: str,
    scoped_files: set[str],
) -> dict[str, dict[str, Any]]:
    return {
        item["id"]: item
        for item in baseline_report.get(key, [])
        if item.get("file") in scoped_files
    }


def _collect_item_regressions(
    *,
    diff_items: dict[str, list[dict[str, Any]]],
    context: _DiffRegressionContext,
) -> None:
    for item_id, item in context.current_items_by_id.items():
        previous = context.baseline_items_by_id.get(item_id)
        if previous is None:
            if context.new_item_is_regression(item):
                diff_items["new"].append(
                    {
                        "kind": context.kind,
                        "id": item_id,
                        "file": item["file"],
                        "symbol": item["symbol"],
                        "after": context.summarize(item),
                    }
                )
            continue
        reasons = context.regression_reasons(previous, item)
        if reasons:
            diff_items["worsened"].append(
                {
                    "kind": context.kind,
                    "id": item_id,
                    "file": item["file"],
                    "symbol": item["symbol"],
                    "before": context.summarize(previous),
                    "after": context.summarize(item),
                    "reasons": reasons,
                }
            )


def _collect_resolved_items(
    *,
    diff_items: dict[str, list[dict[str, Any]]],
    current_items_by_id: dict[str, dict[str, Any]],
    baseline_items_by_id: dict[str, dict[str, Any]],
    kind: str,
    summarize: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    for item_id, item in baseline_items_by_id.items():
        if item_id in current_items_by_id:
            continue
        diff_items["resolved"].append(
            {
                "kind": kind,
                "id": item_id,
                "file": item["file"],
                "symbol": item["symbol"],
                "before": summarize(item),
            }
        )


def _sort_diff_items(diff_items: dict[str, list[dict[str, Any]]]) -> None:
    for key in diff_items:
        diff_items[key].sort(
            key=lambda item: (item["kind"], item["file"], item["symbol"])
        )


def summarize_hotspot(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "classification": item["classification"],
        "tools": item["tools"],
        "metrics": item["metrics"],
    }


def summarize_dead_code(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "classification": item["classification"],
        "confidence": item["confidence"],
        "kind": item["kind"],
        "size": item.get("size"),
    }


def hotspot_new_item_is_regression(
    item: dict[str, Any], *, config: AuditConfig
) -> bool:
    if item["classification"] != "monitor":
        return True
    if set(item.get("tools", [])) != {"lizard"}:
        return True
    return _hotspot_signal_reasons(item, config=config) != {"lizard.nloc"}


def hotspot_regression_reasons(
    previous: dict[str, Any], current: dict[str, Any], *, config: AuditConfig
) -> list[str]:
    reasons: list[str] = []
    if (
        HOTSPOT_CLASSIFICATION_RANK[current["classification"]]
        > HOTSPOT_CLASSIFICATION_RANK[previous["classification"]]
    ):
        reasons.append("classification")

    previous_metrics = previous.get("metrics", {})
    current_metrics = current.get("metrics", {})
    for tool_name, metric_name in (
        ("ruff", "complexity"),
        ("complexipy", "complexity"),
        ("lizard", "ccn"),
        ("lizard", "nloc"),
        ("lizard", "parameter_count"),
    ):
        old_rank = _hotspot_metric_severity_rank(
            tool_name=tool_name,
            metric_name=metric_name,
            value=int(previous_metrics.get(tool_name, {}).get(metric_name, 0)),
            config=config,
        )
        new_rank = _hotspot_metric_severity_rank(
            tool_name=tool_name,
            metric_name=metric_name,
            value=int(current_metrics.get(tool_name, {}).get(metric_name, 0)),
            config=config,
        )
        if new_rank > old_rank:
            reasons.append(f"{tool_name}.{metric_name}")

    if len(set(current.get("tools", []))) > len(set(previous.get("tools", []))):
        reasons.append("tool_overlap")
    return sorted(set(reasons))


def _hotspot_signal_reasons(item: dict[str, Any], *, config: AuditConfig) -> set[str]:
    reasons: set[str] = set()
    metrics = item.get("metrics", {})
    for tool_name, metric_name in (
        ("ruff", "complexity"),
        ("complexipy", "complexity"),
        ("lizard", "ccn"),
        ("lizard", "nloc"),
        ("lizard", "parameter_count"),
    ):
        metric_values = metrics.get(tool_name, {})
        rank = _hotspot_metric_severity_rank(
            tool_name=tool_name,
            metric_name=metric_name,
            value=int(metric_values.get(metric_name, 0)),
            config=config,
        )
        if rank > 0:
            reasons.add(f"{tool_name}.{metric_name}")
    return reasons


def _hotspot_metric_severity_rank(
    *,
    tool_name: str,
    metric_name: str,
    value: int,
    config: AuditConfig,
) -> int:
    if value <= 0:
        return 0

    if tool_name == "ruff":
        severity = config.ruff.classify(value)
    elif tool_name == "complexipy":
        severity = config.complexipy.classify(value)
    elif tool_name == "lizard":
        band = getattr(config.lizard, metric_name)
        severity = band.classify(value)
    else:
        raise ValueError(
            f"Unsupported hotspot metric source: {tool_name}.{metric_name}"
        )

    if severity is None:
        return 0
    return SEVERITY_RANK[severity]


def dead_code_regression_reasons(
    previous: dict[str, Any], current: dict[str, Any]
) -> list[str]:
    reasons: list[str] = []
    order = {"review_candidate": 1, "high_confidence_candidate": 2}
    if order[current["classification"]] > order[previous["classification"]]:
        reasons.append("classification")
    if int(current["confidence"]) > int(previous["confidence"]):
        reasons.append("confidence")
    return reasons


def _resolve_debt_status(
    *,
    hotspots: list[dict[str, Any]],
    baseline_diff: dict[str, Any],
) -> tuple[str, str, int]:
    has_regressions = bool(baseline_diff.get("has_regressions"))
    current_refactor_now = [
        hotspot for hotspot in hotspots if hotspot["classification"] == "refactor_now"
    ]
    current_refactor_soon = any(
        hotspot["classification"] == "refactor_soon" for hotspot in hotspots
    )
    new_refactor_now = any(
        item["kind"] == "hotspot" and item["after"]["classification"] == "refactor_now"
        for item in baseline_diff.get("new", [])
    )
    if has_regressions or new_refactor_now:
        return (
            "corroding",
            "Structural debt is regressing in the current scope.",
            len(current_refactor_now),
        )
    if current_refactor_now or current_refactor_soon:
        return (
            "strained",
            "Existing structural debt remains, but the current scope did not regress.",
            len(current_refactor_now),
        )
    return (
        "stable",
        "No structural debt regressions were detected in the current scope.",
        len(current_refactor_now),
    )


def _build_repo_verdict_summary(
    *,
    base_summary: str,
    routing_pressure: str,
    signal_health: str,
    missing_signals: list[str],
) -> str:
    summary = base_summary
    if routing_pressure in {"investigate_now", "investigate_soon"}:
        summary = f"{summary} Routing pressure is {routing_pressure}."
    if not missing_signals:
        return summary
    missing_label = ", ".join(missing_signals)
    if routing_pressure in {"investigate_now", "investigate_soon"}:
        return (
            f"{base_summary} Routing pressure is {routing_pressure}. "
            f"Signal health is {signal_health}: missing {missing_label}."
        )
    return f"{base_summary} Signal health is {signal_health}: missing {missing_label}."


def build_repo_verdict(
    *,
    hotspots: list[dict[str, Any]],
    baseline_diff: dict[str, Any],
    agent_routing_queue: list[dict[str, Any]],
    history_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    has_regressions = bool(baseline_diff.get("has_regressions"))
    debt_status, base_summary, refactor_now_total = _resolve_debt_status(
        hotspots=hotspots,
        baseline_diff=baseline_diff,
    )
    routing_pressure = _routing_pressure(agent_routing_queue)
    signal_health, missing_signals = _signal_health(
        history_summary=history_summary,
        agent_routing_queue=agent_routing_queue,
    )
    summary = _build_repo_verdict_summary(
        base_summary=base_summary,
        routing_pressure=routing_pressure,
        signal_health=signal_health,
        missing_signals=missing_signals,
    )
    return {
        "status": debt_status,
        "debt_status": debt_status,
        "routing_pressure": routing_pressure,
        "summary": summary,
        "has_regressions": has_regressions,
        "signal_health": signal_health,
        "missing_signals": missing_signals,
        "refactor_now_total": refactor_now_total,
        "investigate_now_total": sum(
            1 for item in agent_routing_queue if item["priority_band"] == "investigate_now"
        ),
        "investigate_soon_total": sum(
            1
            for item in agent_routing_queue
            if item["priority_band"] == "investigate_soon"
        ),
    }


def build_summary(
    *,
    files: list[Path],
    hotspots: list[dict[str, Any]],
    dead_code_candidates: list[dict[str, Any]],
    agent_routing_queue: list[dict[str, Any]],
) -> dict[str, Any]:
    return build_summary_from_file_count(
        file_count=len(files),
        hotspots=hotspots,
        dead_code_candidates=dead_code_candidates,
        agent_routing_queue=agent_routing_queue,
    )


def build_summary_from_file_count(
    *,
    file_count: int,
    hotspots: list[dict[str, Any]],
    dead_code_candidates: list[dict[str, Any]],
    agent_routing_queue: list[dict[str, Any]],
) -> dict[str, Any]:
    hotspot_counter = Counter(item["classification"] for item in hotspots)
    dead_counter = Counter(item["classification"] for item in dead_code_candidates)
    routing_counter = Counter(item["priority_band"] for item in agent_routing_queue)
    return {
        "files_scanned": file_count,
        "hotspots_total": len(hotspots),
        "monitor_total": int(hotspot_counter.get("monitor", 0)),
        "refactor_soon_total": int(hotspot_counter.get("refactor_soon", 0)),
        "refactor_now_total": int(hotspot_counter.get("refactor_now", 0)),
        "dead_code_candidates_total": len(dead_code_candidates),
        "dead_code_high_confidence_total": int(
            dead_counter.get("high_confidence_candidate", 0)
        ),
        "agent_routing_queue_total": len(agent_routing_queue),
        "investigate_now_total": int(routing_counter.get("investigate_now", 0)),
        "investigate_soon_total": int(routing_counter.get("investigate_soon", 0)),
        "watch_total": int(routing_counter.get("watch", 0)),
    }


def _render_repo_verdict_lines(
    *,
    summary: dict[str, Any],
    repo_verdict: dict[str, Any],
) -> list[str]:
    lines = [
        "## Repo verdict",
        "",
        f"- Status: `{repo_verdict['status']}`",
        f"- Debt status: `{repo_verdict.get('debt_status', repo_verdict['status'])}`",
        f"- Routing pressure: `{repo_verdict.get('routing_pressure', 'none')}`",
        f"- Signal health: `{repo_verdict.get('signal_health', 'full')}`",
    ]
    if repo_verdict.get("missing_signals"):
        lines.append(f"- Missing signals: {', '.join(repo_verdict['missing_signals'])}")
    lines.extend(
        [
            f"- Summary: {repo_verdict['summary']}",
            f"- Files scanned: {summary['files_scanned']}",
            f"- Hotspots: {summary['hotspots_total']} total, "
            f"{summary['refactor_now_total']} `refactor_now`, "
            f"{summary['refactor_soon_total']} `refactor_soon`, "
            f"{summary['monitor_total']} `monitor`",
            f"- Agent routing queue: {summary.get('agent_routing_queue_total', 0)} total, "
            f"{summary.get('investigate_now_total', 0)} `investigate_now`, "
            f"{summary.get('investigate_soon_total', 0)} `investigate_soon`, "
            f"{summary.get('watch_total', 0)} `watch`",
            f"- Dead code candidates: {summary['dead_code_candidates_total']} total, "
            f"{summary['dead_code_high_confidence_total']} high-confidence",
        ]
    )
    return lines


def _render_tool_summary_lines(tool_summaries: dict[str, Any]) -> list[str]:
    lines = [
        "## Tool summaries",
        "",
        "| Tool | Total | Warning | High | Critical |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for tool_name in ("ruff", "lizard", "complexipy"):
        item = tool_summaries[tool_name]
        lines.append(
            f"| {tool_name} | {item['findings_total']} | {item['warning']} | "
            f"{item['high']} | {item['critical']} |"
        )
    vulture_summary = tool_summaries["vulture"]
    lines.extend(
        [
            "",
            f"Vulture candidates: {vulture_summary['findings_total']} total, "
            f"{vulture_summary['high_confidence_candidate']} high-confidence, "
            f"{vulture_summary['review_candidate']} review candidates.",
        ]
    )
    return lines


def _coverage_label(coverage: dict[str, Any]) -> str:
    if coverage.get("fraction") is not None:
        return f"{coverage['mode']} {coverage['fraction']:.2f}"
    return str(coverage["mode"])


def _render_agent_routing_lines(
    *,
    agent_routing_queue: list[dict[str, Any]],
    history_summary: dict[str, Any],
) -> list[str]:
    lines = [
        "## Agent routing queue",
        "",
        f"- History status: {history_summary.get('status', 'unavailable')}",
        f"- Lookback days: {history_summary.get('lookback_days', 0)}",
        "",
        "| Priority | Score | File | Change | Coverage | Coupling |",
        "| --- | ---: | --- | --- | --- | --- |",
    ]
    if not agent_routing_queue:
        lines.append("| none | 0 | - | - | - | - |")
        return lines
    for item in agent_routing_queue[:15]:
        change_label = f"{item['change_frequency']} commits / {item['churn']} churn"
        coupling_label = ", ".join(
            f"{coupled['file']} ({coupled['shared_commits']})"
            for coupled in item["top_coupled_files"][:2]
        ) or "-"
        lines.append(
            f"| {item['priority_band']} | {item['priority_score']} | "
            f"{item['file']} | {change_label} | {_coverage_label(item['coverage'])} | "
            f"{coupling_label} |"
        )
    return lines


def _render_hotspot_lines(hotspots: list[dict[str, Any]]) -> list[str]:
    lines = [
        "## Top hotspots",
        "",
        "| Classification | Tools | File | Symbol | Notes |",
        "| --- | ---: | --- | --- | --- |",
    ]
    if not hotspots:
        lines.append("| none | 0 | - | - | - |")
        return lines
    for hotspot in hotspots[:15]:
        notes = ", ".join(
            f"{tool}:{format_tool_metrics(tool, hotspot['metrics'][tool])}"
            for tool in hotspot["tools"]
        )
        lines.append(
            f"| {hotspot['classification']} | {hotspot['tool_count']} | "
            f"{hotspot['file']} | {hotspot['symbol']} | {notes} |"
        )
    return lines


def _render_dead_code_lines(dead_code_candidates: list[dict[str, Any]]) -> list[str]:
    lines = [
        "## Dead code candidates",
        "",
        "| Classification | Confidence | File | Symbol | Kind |",
        "| --- | ---: | --- | --- | --- |",
    ]
    if not dead_code_candidates:
        lines.append("| none | 0 | - | - | - |")
        return lines
    for candidate in dead_code_candidates[:15]:
        lines.append(
            f"| {candidate['classification']} | {candidate['confidence']}% | "
            f"{candidate['file']} | {candidate['symbol']} | {candidate['kind']} |"
        )
    return lines


def _render_baseline_diff_lines(baseline_diff: dict[str, Any]) -> list[str]:
    lines = [
        "## Baseline diff",
        "",
        f"- Baseline available: {baseline_diff['baseline_available']}",
        f"- Regressions detected: {baseline_diff['has_regressions']}",
        f"- New: {len(baseline_diff['new'])}",
        f"- Worsened: {len(baseline_diff['worsened'])}",
        f"- Resolved: {len(baseline_diff['resolved'])}",
    ]
    for label in ("new", "worsened", "resolved"):
        items = baseline_diff[label]
        if not items:
            continue
        lines.extend(["", f"### {label.title()}", ""])
        for item in items[:10]:
            lines.append(f"- `{item['kind']}` {item['file']} :: {item['symbol']}")
    return lines


def render_markdown_report(report: dict[str, Any]) -> str:
    summary = report["summary"]
    repo_verdict = report["repo_verdict"]
    tool_summaries = report["tool_summaries"]
    hotspots = report["hotspots"]
    agent_routing_queue = report.get("agent_routing_queue", [])
    history_summary = report.get("history_summary", {})
    dead_code_candidates = report["dead_code_candidates"]
    baseline_diff = report["baseline_diff"]
    queue = report.get("recommended_queue", report["recommended_refactor_queue"])

    lines = ["# Refactor Audit", ""]
    lines.extend(_render_repo_verdict_lines(summary=summary, repo_verdict=repo_verdict))
    lines.extend([""])
    lines.extend(_render_tool_summary_lines(tool_summaries))
    lines.extend([""])
    lines.extend(
        _render_agent_routing_lines(
            agent_routing_queue=agent_routing_queue,
            history_summary=history_summary,
        )
    )
    lines.extend([""])
    lines.extend(_render_hotspot_lines(hotspots))
    lines.extend([""])
    lines.extend(_render_dead_code_lines(dead_code_candidates))
    lines.extend([""])
    lines.extend(_render_baseline_diff_lines(baseline_diff))

    lines.extend(
        [
            "",
            "## Recommended refactor queue",
            "",
            "| Subsystem | Investigate now | Investigate soon | Watch |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    for item in queue:
        lines.append(
            f"| {item['subsystem']} | {item['investigate_now']} | "
            f"{item['investigate_soon']} | {item['watch']} |"
        )
    return "\n".join(lines) + "\n"


def format_tool_metrics(tool_name: str, metrics: dict[str, int]) -> str:
    if tool_name == "lizard":
        return (
            f"CCN={metrics.get('ccn', 0)}, "
            f"NLOC={metrics.get('nloc', 0)}, "
            f"PARAM={metrics.get('parameter_count', 0)}"
        )
    if tool_name in {"ruff", "complexipy"}:
        return f"complexity={metrics.get('complexity', 0)}"
    return ", ".join(f"{key}={value}" for key, value in sorted(metrics.items()))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _merge_partial_scope_items(
    *,
    baseline_items: list[dict[str, Any]],
    current_items: list[dict[str, Any]],
    scoped_file_set: set[str],
    sort_key: Callable[[dict[str, Any]], tuple[Any, ...]],
) -> list[dict[str, Any]]:
    return sorted(
        [
            item
            for item in baseline_items
            if item.get("file") not in scoped_file_set
        ]
        + current_items,
        key=sort_key,
    )


def _merge_partial_scope_history(
    *,
    baseline_report: dict[str, Any],
    current_history: dict[str, Any],
    scoped_file_set: set[str],
) -> dict[str, Any]:
    baseline_history = baseline_report.get("history_summary", {})
    merged_history_files = dict(baseline_history.get("files", {}))
    merged_history_files.update(
        {
            file_name: item
            for file_name, item in current_history.get("files", {}).items()
            if file_name in scoped_file_set
        }
    )
    return {
        "status": current_history.get(
            "status", baseline_history.get("status", "unavailable")
        ),
        "lookback_days": int(
            current_history.get(
                "lookback_days", baseline_history.get("lookback_days", 0)
            )
        ),
        "max_commit_frequency": max(
            (
                int(item.get("commit_frequency", 0))
                for item in merged_history_files.values()
            ),
            default=0,
        ),
        "max_churn": max(
            (int(item.get("churn", 0)) for item in merged_history_files.values()),
            default=0,
        ),
        "files": dict(sorted(merged_history_files.items())),
    }


def _rebuild_snapshot_rollups(
    *,
    snapshot: dict[str, Any],
    preserved_scope: dict[str, Any],
) -> None:
    scope_files_value = preserved_scope.get("files", [])
    file_count = preserved_scope.get("file_count", len(scope_files_value))
    snapshot["scope"] = preserved_scope
    snapshot["summary"] = build_summary_from_file_count(
        file_count=int(file_count),
        hotspots=snapshot["hotspots"],
        dead_code_candidates=snapshot["dead_code_candidates"],
        agent_routing_queue=snapshot["agent_routing_queue"],
    )
    snapshot["tool_summaries"] = build_tool_summaries_from_snapshot(
        hotspots=snapshot["hotspots"],
        dead_code_candidates=snapshot["dead_code_candidates"],
    )
    recommended_queue = build_recommended_queue(snapshot["agent_routing_queue"])
    snapshot["recommended_queue"] = recommended_queue
    snapshot["recommended_refactor_queue"] = recommended_queue


def build_baseline_snapshot(
    report: dict[str, Any],
    *,
    baseline_report: dict[str, Any] | None = None,
    scope_files: Iterable[str] | None = None,
) -> dict[str, Any]:
    snapshot = dict(report)
    scoped_file_set = set(scope_files or [])
    if baseline_report is not None:
        _require_supported_baseline_report(baseline_report)
    if baseline_report is not None and scoped_file_set:
        snapshot["hotspots"] = _merge_partial_scope_items(
            baseline_items=baseline_report.get("hotspots", []),
            current_items=snapshot["hotspots"],
            scoped_file_set=scoped_file_set,
            sort_key=hotspot_sort_key,
        )
        snapshot["dead_code_candidates"] = _merge_partial_scope_items(
            baseline_items=baseline_report.get("dead_code_candidates", []),
            current_items=snapshot["dead_code_candidates"],
            scoped_file_set=scoped_file_set,
            sort_key=dead_code_sort_key,
        )
        snapshot["agent_routing_queue"] = _merge_partial_scope_items(
            baseline_items=baseline_report.get("agent_routing_queue", []),
            current_items=snapshot["agent_routing_queue"],
            scoped_file_set=scoped_file_set,
            sort_key=agent_routing_sort_key,
        )
        snapshot["history_summary"] = _merge_partial_scope_history(
            baseline_report=baseline_report,
            current_history=snapshot.get("history_summary", {}),
            scoped_file_set=scoped_file_set,
        )
        preserved_scope = baseline_report.get("scope", snapshot["scope"])
        _rebuild_snapshot_rollups(snapshot=snapshot, preserved_scope=preserved_scope)
    snapshot["baseline_diff"] = {
        "baseline_available": False,
        "baseline_path": None,
        "has_regressions": False,
        "new": [],
        "worsened": [],
        "resolved": [],
    }
    snapshot["repo_verdict"] = build_repo_verdict(
        hotspots=snapshot["hotspots"],
        baseline_diff=snapshot["baseline_diff"],
        agent_routing_queue=snapshot.get("agent_routing_queue", []),
        history_summary=snapshot.get("history_summary"),
    )
    return snapshot


def _coerce_refactor_audit_run_request(
    *,
    request: RefactorAuditRunRequest | None = None,
    legacy_kwargs: dict[str, Any] | None = None,
) -> RefactorAuditRunRequest:
    if request is not None:
        return request
    values = dict(legacy_kwargs or {})
    config = values["config"]
    lookback_value = values.get("lookback_days")
    coverage_value = values.get("coverage_json", config.coverage.coverage_json)
    return RefactorAuditRunRequest(
        scope_targets=list(values["scope_targets"]),
        out_dir=Path(values["out_dir"]),
        baseline_path=Path(values["baseline_path"]),
        update_baseline=bool(values["update_baseline"]),
        fail_on_regression=bool(values["fail_on_regression"]),
        lookback_days=int(
            config.history.lookback_days if lookback_value is None else lookback_value
        ),
        coverage_json=None if coverage_value is None else Path(coverage_value),
        config=config,
    )


def _prepare_audit_scope(request: RefactorAuditRunRequest) -> AuditScopeState:
    files = collect_python_files(
        repo_root=request.config.repo_root,
        targets=request.scope_targets,
        exclude_patterns=request.config.exclude,
    )
    default_scope_files = collect_python_files(
        repo_root=request.config.repo_root,
        targets=list(request.config.targets),
        exclude_patterns=request.config.exclude,
    )
    if not files:
        raise RuntimeError("No Python files matched the requested scope.")
    lookup = ScopeLookup.from_files(
        repo_root=request.config.repo_root,
        files=files,
        ignored_decorators=_routing.get_active_profile().dead_code_ignored_decorators,
    )
    request.out_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = request.out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    current_scope_files = [
        relative_path(path, request.config.repo_root) for path in files
    ]
    full_scope_file_set = {
        relative_path(path, request.config.repo_root) for path in default_scope_files
    }
    return AuditScopeState(
        files=files,
        current_scope_files=current_scope_files,
        default_scope_files=tuple(sorted(full_scope_file_set)),
        is_partial_scope=set(current_scope_files) != full_scope_file_set,
        lookup=lookup,
        raw_dir=raw_dir,
    )


def _history_collection_inputs(
    *,
    request: RefactorAuditRunRequest,
    scope_state: AuditScopeState,
) -> tuple[list[str], tuple[str, ...]]:
    targets = list(request.config.targets)
    tracked_files = set(scope_state.default_scope_files)
    extra_scope_files = sorted(set(scope_state.current_scope_files) - tracked_files)
    if extra_scope_files:
        targets.extend(extra_scope_files)
        tracked_files.update(extra_scope_files)
    return list(dict.fromkeys(targets)), tuple(sorted(tracked_files))


def _run_ruff_audit(
    *,
    file_args: list[str],
    raw_dir: Path,
    lookup: ScopeLookup,
    config: AuditConfig,
) -> list[HotspotSignal]:
    completed = run_command(
        [
            "ruff",
            "check",
            *file_args,
            "--select",
            "C90",
            "--output-format",
            "json",
        ],
        cwd=config.repo_root,
        allowed_returncodes={0, 1},
    )
    raw_path = raw_dir / "ruff.json"
    raw_path.write_text(completed.stdout or "[]", encoding="utf-8")
    return parse_ruff_findings(
        raw_text=completed.stdout,
        lookup=lookup,
        config=config,
    )


def _run_lizard_audit(
    *,
    file_args: list[str],
    raw_dir: Path,
    lookup: ScopeLookup,
    config: AuditConfig,
) -> list[HotspotSignal]:
    completed = run_command(
        ["lizard", *file_args, "-l", "python", "--csv"],
        cwd=config.repo_root,
        allowed_returncodes={0, 1},
    )
    raw_path = raw_dir / "lizard.csv"
    raw_path.write_text(completed.stdout, encoding="utf-8")
    return parse_lizard_findings(
        raw_text=completed.stdout,
        lookup=lookup,
        config=config,
    )


def _run_complexipy_audit(
    *,
    file_args: list[str],
    raw_dir: Path,
    lookup: ScopeLookup,
    config: AuditConfig,
) -> list[HotspotSignal]:
    raw_path = raw_dir / "complexipy.json"
    with tempfile.TemporaryDirectory(
        dir=raw_dir,
        prefix="complexipy-run-",
    ) as complexipy_temp_dir:
        temp_dir_path = Path(complexipy_temp_dir)
        completed = run_command(
            [
                "complexipy",
                *file_args,
                "--max-complexity-allowed",
                str(config.complexipy.warning_min - 1),
                "--output-format",
                "json",
                "--color",
                "no",
            ],
            cwd=temp_dir_path,
            allowed_returncodes={0, 1},
        )
        generated = list(temp_dir_path.glob("*.json"))
        if not generated:
            raise RuntimeError(
                "complexipy did not emit a JSON report. "
                + (completed.stderr.strip() or completed.stdout.strip())
            )
        latest = max(generated, key=lambda path: path.stat().st_mtime_ns)
        raw_path.write_text(
            latest.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
    return parse_complexipy_findings(
        raw_text=raw_path.read_text(encoding="utf-8"),
        lookup=lookup,
        config=config,
    )


def _run_vulture_audit(
    *,
    file_args: list[str],
    raw_dir: Path,
    lookup: ScopeLookup,
    config: AuditConfig,
) -> list[dict[str, Any]]:
    completed = run_command(
        [
            "vulture",
            *file_args,
            "--min-confidence",
            str(config.vulture.review_candidate_min),
        ],
        cwd=config.repo_root,
        allowed_returncodes={0, 3},
    )
    raw_path = raw_dir / "vulture.txt"
    raw_path.write_text(completed.stdout, encoding="utf-8")
    return parse_vulture_candidates(
        raw_text=completed.stdout,
        lookup=lookup,
        config=config,
    )


def _run_audit_tools(
    scope_state: AuditScopeState,
    request: RefactorAuditRunRequest,
) -> AuditToolRunResult:
    file_args = [str(path) for path in scope_state.files]
    return AuditToolRunResult(
        ruff_signals=_run_ruff_audit(
            file_args=file_args,
            raw_dir=scope_state.raw_dir,
            lookup=scope_state.lookup,
            config=request.config,
        ),
        lizard_signals=_run_lizard_audit(
            file_args=file_args,
            raw_dir=scope_state.raw_dir,
            lookup=scope_state.lookup,
            config=request.config,
        ),
        complexipy_signals=_run_complexipy_audit(
            file_args=file_args,
            raw_dir=scope_state.raw_dir,
            lookup=scope_state.lookup,
            config=request.config,
        ),
        dead_code_candidates=_run_vulture_audit(
            file_args=file_args,
            raw_dir=scope_state.raw_dir,
            lookup=scope_state.lookup,
            config=request.config,
        ),
    )


def _require_supported_baseline_report(baseline_report: dict[str, Any]) -> None:
    schema_version = optional_int(baseline_report.get("schema_version"))
    if schema_version is None or schema_version < SCHEMA_VERSION:
        raise RuntimeError(
            f"Baseline schema version {schema_version!r} is no longer supported. "
            f"Regenerate the baseline with Cremona schema version {SCHEMA_VERSION}."
        )


def _baseline_report_is_supported(baseline_report: dict[str, Any]) -> bool:
    schema_version = optional_int(baseline_report.get("schema_version"))
    return schema_version is not None and schema_version >= SCHEMA_VERSION


def _load_baseline_report(
    baseline_path: Path,
    *,
    require_supported_schema: bool = True,
) -> dict[str, Any] | None:
    if not baseline_path.exists():
        return None
    baseline_report = json.loads(baseline_path.read_text(encoding="utf-8"))
    if require_supported_schema:
        _require_supported_baseline_report(baseline_report)
    baseline_report["_baseline_path"] = str(baseline_path)
    return baseline_report


def _build_audit_report(
    context: _AuditReportContext,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "scope": {
            "requested_targets": context.request.scope_targets,
            "files": context.scope_state.current_scope_files,
            "file_count": len(context.scope_state.files),
            "repo_root": str(context.request.config.repo_root),
        },
        "summary": build_summary(
            files=context.scope_state.files,
            hotspots=context.hotspots,
            dead_code_candidates=context.dead_code_candidates,
            agent_routing_queue=context.agent_routing_queue,
        ),
        "repo_verdict": context.repo_verdict,
        "history_summary": context.history_summary,
        "tool_summaries": context.tool_summaries,
        "hotspots": context.hotspots,
        "dead_code_candidates": context.dead_code_candidates,
        "agent_routing_queue": context.agent_routing_queue,
        "baseline_diff": context.baseline_diff,
        "recommended_queue": build_recommended_queue(context.agent_routing_queue),
        "recommended_refactor_queue": build_recommended_queue(
            context.agent_routing_queue
        ),
    }


def _build_hotspots_and_tool_summaries(
    *,
    tool_run: AuditToolRunResult,
    config: AuditConfig,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    hotspots = aggregate_hotspots(
        tool_run.ruff_signals + tool_run.lizard_signals + tool_run.complexipy_signals,
        config=config,
    )
    tool_summaries = build_tool_summaries(
        ruff_signals=tool_run.ruff_signals,
        lizard_signals=tool_run.lizard_signals,
        complexipy_signals=tool_run.complexipy_signals,
        dead_code_candidates=tool_run.dead_code_candidates,
    )
    return hotspots, tool_summaries


def _collect_history_summary_for_scope(
    *,
    request: RefactorAuditRunRequest,
    scope_state: AuditScopeState,
) -> dict[str, Any]:
    history_targets, history_tracked_files = _history_collection_inputs(
        request=request,
        scope_state=scope_state,
    )
    return collect_git_history_summary(
        request=_GitHistoryCollectionRequest(
            repo_root=request.config.repo_root,
            targets=tuple(history_targets),
            tracked_files=history_tracked_files,
            current_scope_files=tuple(scope_state.current_scope_files),
            lookback_days=request.lookback_days,
            min_shared_commits=request.config.history.min_shared_commits,
            coupling_ignore_commit_file_count=request.config.history.coupling_ignore_commit_file_count,
            raw_path=scope_state.raw_dir / "git-history.txt",
        )
    )


def _build_agent_routing_queue_for_scope(
    *,
    request: RefactorAuditRunRequest,
    scope_state: AuditScopeState,
    hotspots: list[dict[str, Any]],
    dead_code_candidates: list[dict[str, Any]],
    history_summary: dict[str, Any],
) -> list[dict[str, Any]]:
    coverage_summary = load_coverage_summary(
        coverage_json=request.coverage_json,
        repo_root=request.config.repo_root,
        tracked_files=scope_state.current_scope_files,
    )
    routing_index = build_agent_routing_index(
        repo_root=request.config.repo_root,
        files=scope_state.files,
    )
    return build_agent_routing_queue(
        scope_files=scope_state.current_scope_files,
        hotspots=hotspots,
        dead_code_candidates=dead_code_candidates,
        history_summary=history_summary,
        coverage_summary=coverage_summary,
        routing_index=routing_index,
    )


def _load_comparable_baseline_report(
    *,
    request: RefactorAuditRunRequest,
    scope_state: AuditScopeState,
) -> dict[str, Any] | None:
    baseline_report = _load_baseline_report(
        request.baseline_path,
        require_supported_schema=not (
            request.update_baseline and not scope_state.is_partial_scope
        ),
    )
    if baseline_report is not None and not _baseline_report_is_supported(
        baseline_report
    ):
        return None
    return baseline_report


def _execute_refactor_audit(
    *,
    request: RefactorAuditRunRequest,
    scope_state: AuditScopeState,
    tool_run: AuditToolRunResult,
) -> _AuditExecutionResult:
    hotspots, tool_summaries = _build_hotspots_and_tool_summaries(
        tool_run=tool_run,
        config=request.config,
    )
    history_summary = _collect_history_summary_for_scope(
        request=request,
        scope_state=scope_state,
    )
    agent_routing_queue = _build_agent_routing_queue_for_scope(
        request=request,
        scope_state=scope_state,
        hotspots=hotspots,
        dead_code_candidates=tool_run.dead_code_candidates,
        history_summary=history_summary,
    )
    baseline_report = _load_comparable_baseline_report(
        request=request,
        scope_state=scope_state,
    )
    baseline_diff = build_baseline_diff(
        current_hotspots=hotspots,
        current_dead_code_candidates=tool_run.dead_code_candidates,
        baseline_report=baseline_report,
        scope_files=scope_state.current_scope_files,
        config=request.config,
    )
    repo_verdict = build_repo_verdict(
        hotspots=hotspots,
        baseline_diff=baseline_diff,
        agent_routing_queue=agent_routing_queue,
        history_summary=history_summary,
    )
    report = _build_audit_report(
        _AuditReportContext(
            request=request,
            scope_state=scope_state,
            hotspots=hotspots,
            dead_code_candidates=tool_run.dead_code_candidates,
            agent_routing_queue=agent_routing_queue,
            history_summary=history_summary,
            tool_summaries=tool_summaries,
            baseline_diff=baseline_diff,
            repo_verdict=repo_verdict,
        )
    )
    return _AuditExecutionResult(
        report=report,
        baseline_report=baseline_report,
        baseline_diff=baseline_diff,
    )


def _write_audit_outputs(*, out_dir: Path, report: dict[str, Any]) -> None:
    write_json(out_dir / "report.json", report)
    (out_dir / "report.md").write_text(render_markdown_report(report), encoding="utf-8")


def _maybe_update_baseline(
    *,
    request: RefactorAuditRunRequest,
    scope_state: AuditScopeState,
    baseline_report: dict[str, Any] | None,
    report: dict[str, Any],
) -> None:
    if not request.update_baseline:
        return
    if scope_state.is_partial_scope and baseline_report is None:
        raise RuntimeError(
            "--update-baseline requires an existing baseline when auditing a partial scope."
        )
    write_json(
        request.baseline_path,
        build_baseline_snapshot(
            report,
            baseline_report=baseline_report if scope_state.is_partial_scope else None,
            scope_files=scope_state.current_scope_files
            if scope_state.is_partial_scope
            else None,
        ),
    )


def run_refactor_audit(
    request: RefactorAuditRunRequest | None = None,
    **legacy_kwargs: Any,
) -> tuple[int, dict[str, Any]]:
    resolved_request = _coerce_refactor_audit_run_request(
        request=request,
        legacy_kwargs=legacy_kwargs,
    )
    previous_profile = _set_active_profile(
        get_profile(
            resolved_request.config.profile,
            resolved_request.config.profile_registry,
        )
    )
    try:
        scope_state = _prepare_audit_scope(resolved_request)
        tool_run = _run_audit_tools(scope_state, resolved_request)
        execution = _execute_refactor_audit(
            request=resolved_request,
            scope_state=scope_state,
            tool_run=tool_run,
        )
        _write_audit_outputs(out_dir=resolved_request.out_dir, report=execution.report)
        _maybe_update_baseline(
            request=resolved_request,
            scope_state=scope_state,
            baseline_report=execution.baseline_report,
            report=execution.report,
        )
        exit_code = int(
            bool(
                resolved_request.fail_on_regression
                and execution.baseline_diff["has_regressions"]
            )
        )
        return exit_code, execution.report
    finally:
        _set_active_profile(previous_profile)


def infer_repo_root(scope_targets: list[str]) -> Path:
    cwd = Path.cwd().resolve()
    if not scope_targets:
        return cwd
    roots: list[Path] = []
    for target in scope_targets:
        candidate = Path(target)
        resolved = candidate.resolve() if candidate.is_absolute() else (cwd / candidate).resolve()
        roots.append(resolved if resolved.is_dir() else resolved.parent)
    if all(path == cwd or cwd in path.parents for path in roots):
        return cwd
    return Path(os.path.commonpath([str(path) for path in roots])).resolve()


def run_scan(request: ScanRequest) -> ScanReport:
    repo_root = infer_repo_root(request.scope_targets)
    config = request.config or load_audit_config(repo_root=repo_root)
    profile = request.profile or config.profile
    profile_name = profile.name if isinstance(profile, Profile) else str(profile)
    get_profile(profile_name, config.profile_registry)
    resolved_config = AuditConfig(
        repo_root=config.repo_root,
        profile=profile_name,
        profile_registry=config.profile_registry,
        targets=config.targets,
        exclude=config.exclude,
        out_dir=config.out_dir,
        baseline=config.baseline,
        ruff=config.ruff,
        lizard=config.lizard,
        complexipy=config.complexipy,
        vulture=config.vulture,
        history=config.history,
        coverage=config.coverage,
    )
    internal_request = RefactorAuditRunRequest(
        scope_targets=request.scope_targets,
        out_dir=request.out_dir,
        baseline_path=request.baseline_path,
        update_baseline=request.update_baseline,
        fail_on_regression=request.fail_on_regression,
        lookback_days=(
            resolved_config.history.lookback_days
            if request.lookback_days is None
            else int(request.lookback_days)
        ),
        coverage_json=request.coverage_json,
        config=resolved_config,
    )
    exit_code, payload = run_refactor_audit(request=internal_request)
    return ScanReport(payload=payload, exit_code=exit_code)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit refactor hotspots using ruff, lizard, complexipy, and vulture."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Optional files or directories to audit. Defaults to tool.cremona.targets.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        help="Override the report output directory.",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        help="Override the baseline JSON path.",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Write the current report to the baseline path.",
    )
    parser.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="Exit non-zero when the current scope regresses relative to the baseline.",
    )
    parser.add_argument(
        "--lookback-days",
        type=int,
        help="Override the git history lookback window for agent routing.",
    )
    parser.add_argument(
        "--coverage-json",
        type=Path,
        help="Optional coverage.py JSON report for routing risk scoring.",
    )
    parser.add_argument(
        "--profile",
        help=(
            "Profile name. Defaults to tool.cremona.profile or generic-python. "
            "Custom profiles live under tool.cremona.profiles."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo_root = infer_repo_root(args.paths)
    config = load_audit_config(repo_root=repo_root)
    scope_targets = args.paths or list(config.targets)
    out_dir = args.out_dir.resolve() if args.out_dir is not None else config.out_dir
    baseline_path = (
        args.baseline.resolve() if args.baseline is not None else config.baseline
    )
    lookback_days = (
        int(args.lookback_days)
        if args.lookback_days is not None
        else config.history.lookback_days
    )
    coverage_json = (
        args.coverage_json.resolve()
        if args.coverage_json is not None
        else config.coverage.coverage_json
    )
    report = run_scan(
        ScanRequest(
            scope_targets=scope_targets,
            out_dir=out_dir,
            baseline_path=baseline_path,
            update_baseline=bool(args.update_baseline),
            fail_on_regression=bool(args.fail_on_regression),
            lookback_days=lookback_days,
            coverage_json=coverage_json,
            config=config,
            profile=args.profile or config.profile,
        )
    )
    print(
        f"[{report['repo_verdict']['status']}] {report['repo_verdict']['summary']} "
        f"Report: {out_dir / 'report.md'}"
    )
    return report.exit_code


load_scan_config = load_audit_config


if __name__ == "__main__":
    raise SystemExit(main())
