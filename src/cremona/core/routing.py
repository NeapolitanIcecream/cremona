from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any, Literal, Mapping

from ..profiles import DEFAULT_PROFILE, Profile, empty_routing_signals
from .history import _empty_history_file_summary
from .models import HOTSPOT_CLASSIFICATION_RANK, RoutingFileContext

QUEUE_ORDER = tuple(DEFAULT_PROFILE.queue_order)
_ACTIVE_PROFILE = DEFAULT_PROFILE


def get_active_profile() -> Profile:
    return _ACTIVE_PROFILE


def set_active_profile(profile: Profile) -> Profile:
    global _ACTIVE_PROFILE
    global QUEUE_ORDER
    previous = _ACTIVE_PROFILE
    _ACTIVE_PROFILE = profile
    QUEUE_ORDER = tuple(profile.queue_order)
    return previous


def infer_subsystem(rel_path: str) -> str:
    return _ACTIVE_PROFILE.classify_subsystem(rel_path)


def hotspot_sort_key(item: dict[str, Any]) -> tuple[Any, ...]:
    metrics = item.get("metrics", {})
    return (
        -HOTSPOT_CLASSIFICATION_RANK[item["classification"]],
        -int(metrics.get("complexipy", {}).get("complexity", 0)),
        -int(metrics.get("lizard", {}).get("ccn", 0)),
        -int(metrics.get("lizard", {}).get("nloc", 0)),
        -int(metrics.get("ruff", {}).get("complexity", 0)),
        item["file"],
        item["symbol"],
    )


def _unknown_coverage_summary() -> dict[str, Any]:
    return {
        "mode": "unknown",
        "fraction": None,
    }


def build_agent_routing_index(
    *,
    repo_root: Path,
    files: list[Path],
) -> dict[str, dict[str, int]]:
    return _ACTIVE_PROFILE.build_routing_index(repo_root, files)


def _empty_routing_signals() -> dict[str, int]:
    return empty_routing_signals(_ACTIVE_PROFILE)


def _summarize_file_hotspots(file_hotspots: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(file_hotspots, key=hotspot_sort_key)
    monitor_count = sum(1 for item in ordered if item["classification"] == "monitor")
    multi_tool_monitor = sum(
        1
        for item in ordered
        if item["classification"] == "monitor" and int(item.get("tool_count", 0)) > 1
    )
    return {
        "refactor_now": sum(
            1 for item in ordered if item["classification"] == "refactor_now"
        ),
        "refactor_soon": sum(
            1 for item in ordered if item["classification"] == "refactor_soon"
        ),
        "monitor": monitor_count,
        "multi_tool_monitor": multi_tool_monitor,
        "top_symbols": [
            {
                "symbol": item["symbol"],
                "classification": item["classification"],
            }
            for item in ordered[:5]
        ],
    }


def _priority_band(
    priority_score: int,
) -> Literal["watch", "investigate_soon", "investigate_now"]:
    if priority_score >= 60:
        return "investigate_now"
    if priority_score >= 35:
        return "investigate_soon"
    return "watch"


def _routing_pressure(agent_routing_queue: list[dict[str, Any]]) -> str:
    if any(item["priority_band"] == "investigate_now" for item in agent_routing_queue):
        return "investigate_now"
    if any(
        item["priority_band"] == "investigate_soon" for item in agent_routing_queue
    ):
        return "investigate_soon"
    if agent_routing_queue:
        return "watch_only"
    return "none"


def _count_dead_code_candidates(
    file_dead_code: list[dict[str, Any]],
) -> tuple[int, int]:
    high_confidence_dead_code = sum(
        1
        for item in file_dead_code
        if item["classification"] == "high_confidence_candidate"
    )
    review_candidate_dead_code = sum(
        1 for item in file_dead_code if item["classification"] == "review_candidate"
    )
    return (high_confidence_dead_code, review_candidate_dead_code)


def _change_score(
    *,
    commit_frequency: int,
    churn: int,
    max_commit_frequency: int,
    max_churn: int,
) -> int:
    score = 0
    if max_commit_frequency > 0:
        score += round(20 * commit_frequency / max_commit_frequency)
    if max_churn > 0:
        score += round(10 * churn / max_churn)
    return score


def _coupling_score(top_coupled_files: list[dict[str, Any]]) -> int:
    max_shared_commits = max(
        (int(item.get("shared_commits", 0)) for item in top_coupled_files),
        default=0,
    )
    return min(15, 2 * len(top_coupled_files) + min(5, max_shared_commits))


def _static_score(hotspot_summary: dict[str, Any]) -> int:
    return min(
        20,
        5 * int(hotspot_summary["refactor_now"])
        + 3 * int(hotspot_summary["refactor_soon"])
        + int(hotspot_summary["monitor"])
        + int(hotspot_summary["multi_tool_monitor"]),
    )


def _dead_code_score(
    *,
    high_confidence_dead_code: int,
    review_candidate_dead_code: int,
) -> int:
    return min(
        10,
        3 * high_confidence_dead_code + review_candidate_dead_code // 4,
    )


def _coverage_risk_score(coverage_entry: dict[str, Any]) -> int:
    coverage_fraction = coverage_entry.get("fraction")
    if coverage_fraction is None:
        return 0
    return round((1 - float(coverage_fraction)) * 10)


def _priority_score_floor(hotspot_summary: dict[str, Any]) -> int:
    if int(hotspot_summary.get("refactor_now", 0)) > 0:
        return 35
    return 0


def _routing_priority_components(
    context: RoutingFileContext,
) -> tuple[dict[str, int], list[str]]:
    commit_frequency = int(context.history_entry.get("commit_frequency", 0))
    churn = int(context.history_entry.get("churn", 0))
    top_coupled_files = list(context.history_entry.get("top_coupled_files", []))
    hotspot_summary = _summarize_file_hotspots(context.file_hotspots)
    change_score = _change_score(
        commit_frequency=commit_frequency,
        churn=churn,
        max_commit_frequency=context.max_commit_frequency,
        max_churn=context.max_churn,
    )
    coupling_score = _coupling_score(top_coupled_files)
    high_confidence_dead_code, review_candidate_dead_code = _count_dead_code_candidates(
        context.file_dead_code
    )
    components = {
        "change_score": change_score,
        "coupling_score": coupling_score,
        "static_score": _static_score(hotspot_summary),
        "subsystem_priority_score": _ACTIVE_PROFILE.subsystem_priority_score(
            infer_subsystem(context.file_name)
        ),
        "dead_code_score": _dead_code_score(
            high_confidence_dead_code=high_confidence_dead_code,
            review_candidate_dead_code=review_candidate_dead_code,
        ),
        "coverage_risk_score": _coverage_risk_score(context.coverage_entry),
    }
    components["routing_signal_score"] = _ACTIVE_PROFILE.routing_signal_score(
        context.routing_signals
    )
    routing_bonus_score, triggered = _ACTIVE_PROFILE.evaluate_routing_bonus_rules(
        routing_signals=context.routing_signals,
        components=components,
    )
    components["routing_bonus_score"] = routing_bonus_score
    return (components, triggered)


def _build_agent_routing_item(context: RoutingFileContext) -> dict[str, Any]:
    hotspot_summary = _summarize_file_hotspots(context.file_hotspots)
    priority_components, routing_rules_triggered = _routing_priority_components(context)
    priority_score = max(
        _priority_score_floor(hotspot_summary),
        max(0, min(100, sum(priority_components.values()))),
    )
    return {
        "file": context.file_name,
        "subsystem": infer_subsystem(context.file_name),
        "priority_score": priority_score,
        "priority_band": _priority_band(priority_score),
        "change_frequency": int(context.history_entry.get("commit_frequency", 0)),
        "churn": int(context.history_entry.get("churn", 0)),
        "top_coupled_files": list(context.history_entry.get("top_coupled_files", [])),
        "hotspot_summary": hotspot_summary,
        "routing_signals": context.routing_signals,
        "routing_rules_triggered": routing_rules_triggered,
        "dead_code_candidate_count": len(context.file_dead_code),
        "coverage": dict(context.coverage_entry),
        "priority_components": priority_components,
    }


def build_agent_routing_queue(
    *,
    scope_files: list[str],
    hotspots: list[dict[str, Any]],
    dead_code_candidates: list[dict[str, Any]],
    history_summary: dict[str, Any],
    coverage_summary: dict[str, Any],
    routing_index: dict[str, dict[str, int]],
) -> list[dict[str, Any]]:
    hotspots_by_file: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for hotspot in hotspots:
        hotspots_by_file[hotspot["file"]].append(hotspot)
    dead_code_by_file: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for candidate in dead_code_candidates:
        dead_code_by_file[candidate["file"]].append(candidate)

    max_commit_frequency = int(history_summary.get("max_commit_frequency", 0))
    max_churn = int(history_summary.get("max_churn", 0))
    queue: list[dict[str, Any]] = []
    for file_name in sorted(set(scope_files)):
        history_entry = history_summary.get("files", {}).get(
            file_name, _empty_history_file_summary()
        )
        coverage_entry = coverage_summary.get("files", {}).get(
            file_name, _unknown_coverage_summary()
        )
        routing_signals = dict(
            routing_index.get(file_name, _empty_routing_signals())
        )
        file_dead_code = dead_code_by_file.get(file_name, [])
        queue.append(
            _build_agent_routing_item(
                RoutingFileContext(
                    file_name=file_name,
                    history_entry=history_entry,
                    coverage_entry=coverage_entry,
                    routing_signals=routing_signals,
                    file_hotspots=hotspots_by_file.get(file_name, []),
                    file_dead_code=file_dead_code,
                    max_commit_frequency=max_commit_frequency,
                    max_churn=max_churn,
                )
            )
        )
    queue.sort(key=agent_routing_sort_key)
    return queue


def agent_routing_sort_key(item: dict[str, Any]) -> tuple[Any, ...]:
    components = item.get("priority_components", {})
    return (
        -int(item["priority_score"]),
        -int(components.get("static_score", 0)),
        -int(components.get("change_score", 0)),
        item["file"],
    )


def _group_agent_routing_queue(
    agent_routing_queue: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {name: [] for name in QUEUE_ORDER}
    for item in agent_routing_queue:
        grouped.setdefault(item["subsystem"], []).append(item)
    return grouped


def _sorted_subsystem_items(
    grouped: Mapping[str, list[dict[str, Any]]],
    subsystem: str,
) -> list[dict[str, Any]]:
    return sorted(grouped.get(subsystem, []), key=agent_routing_sort_key)


def _priority_band_count(
    items: list[dict[str, Any]],
    priority_band: str,
) -> int:
    return sum(1 for item in items if item["priority_band"] == priority_band)


def _top_targets(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "file": item["file"],
            "priority_band": item["priority_band"],
            "priority_score": item["priority_score"],
        }
        for item in items[:5]
    ]


def _recommended_queue_entry(
    *,
    subsystem: str,
    items: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "subsystem": subsystem,
        "investigate_now": _priority_band_count(items, "investigate_now"),
        "investigate_soon": _priority_band_count(items, "investigate_soon"),
        "watch": _priority_band_count(items, "watch"),
        "top_targets": _top_targets(items),
    }


def _extra_subsystems(
    grouped: Mapping[str, list[dict[str, Any]]],
) -> list[str]:
    return sorted(
        subsystem
        for subsystem in grouped
        if subsystem not in QUEUE_ORDER and grouped[subsystem]
    )


def build_recommended_queue(agent_routing_queue: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped = _group_agent_routing_queue(agent_routing_queue)
    ordered_subsystems = [*QUEUE_ORDER, *_extra_subsystems(grouped)]
    return [
        _recommended_queue_entry(
            subsystem=subsystem,
            items=_sorted_subsystem_items(grouped, subsystem),
        )
        for subsystem in ordered_subsystems
    ]
