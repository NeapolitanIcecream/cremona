from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from ..python_tools.engine import dead_code_sort_key, optional_int
from .models import (
    HOTSPOT_CLASSIFICATION_RANK,
    SCHEMA_VERSION,
    SEVERITY_RANK,
    AuditConfig,
    _DiffRegressionContext,
)
from .reporting import (
    build_repo_verdict,
    build_summary_from_file_count,
    build_tool_summaries_from_snapshot,
)
from .routing import (
    agent_routing_sort_key,
    build_recommended_queue,
    hotspot_sort_key,
)


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
    snapshot.pop("diagnostics", None)
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
