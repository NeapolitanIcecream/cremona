from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from .models import SEVERITY_RANK, HotspotSignal
from .routing import _routing_pressure


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
