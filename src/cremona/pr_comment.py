from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

COMMENT_MARKER = "<!-- cremona-report -->"
FALLBACK_MESSAGE = "Cremona did not produce a report. See workflow logs."


def _code(value: object) -> str:
    return f"`{value}`"


def _bool_label(value: object) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)


def _coverage_label(coverage: Mapping[str, Any]) -> str:
    fraction = coverage.get("fraction")
    mode = str(coverage.get("mode", "unknown"))
    if fraction is None:
        return mode
    return f"{mode} {float(fraction):.2f}"


def _baseline_counts(baseline_diff: Mapping[str, Any]) -> tuple[int, int, int]:
    return (
        len(list(baseline_diff.get("new", []))),
        len(list(baseline_diff.get("worsened", []))),
        len(list(baseline_diff.get("resolved", []))),
    )


def _render_routing_lines(
    agent_routing_queue: Sequence[Mapping[str, Any]],
    *,
    max_comment_rows: int,
) -> list[str]:
    lines = [
        "### Top routing rows",
        "",
        "| Priority | Score | File | Change | Coverage |",
        "| --- | ---: | --- | --- | --- |",
    ]
    rows = list(agent_routing_queue[: max(0, max_comment_rows)])
    if not rows:
        lines.append("| `none` | 0 | - | - | - |")
        return lines

    for item in rows:
        change_label = (
            f"{item.get('change_frequency', 0)} commits / {item.get('churn', 0)} churn"
        )
        lines.append(
            "| "
            f"{_code(item.get('priority_band', 'none'))} | "
            f"{item.get('priority_score', 0)} | "
            f"{_code(item.get('file', '-'))} | "
            f"{_code(change_label)} | "
            f"{_code(_coverage_label(item.get('coverage', {})))} |"
        )
    return lines


def _render_hotspot_lines(
    hotspots: Sequence[Mapping[str, Any]],
    *,
    max_hotspots: int,
) -> list[str]:
    lines = [
        "### Top hotspots",
        "",
        "| Classification | File | Symbol | Tools |",
        "| --- | --- | --- | --- |",
    ]
    rows = list(hotspots[: max(0, max_hotspots)])
    if not rows:
        lines.append("| `none` | - | - | - |")
        return lines

    for hotspot in rows:
        tools = ", ".join(str(tool) for tool in hotspot.get("tools", [])) or "-"
        lines.append(
            "| "
            f"{_code(hotspot.get('classification', 'none'))} | "
            f"{_code(hotspot.get('file', '-'))} | "
            f"{_code(hotspot.get('symbol', '-'))} | "
            f"{_code(tools)} |"
        )
    return lines


def _render_footer(*, artifact_name: str, artifact_enabled: bool) -> str:
    if artifact_enabled:
        return (
            f"Full report: see the {_code(artifact_name)} artifact and the workflow summary."
        )
    return "Full report: see the workflow summary."


def render_fallback_comment() -> str:
    return "\n".join(
        [
            COMMENT_MARKER,
            "## Cremona report",
            "",
            FALLBACK_MESSAGE,
            "",
        ]
    )


def render_pr_comment(
    report: Mapping[str, Any],
    *,
    max_comment_rows: int,
    max_hotspots: int,
    artifact_name: str,
    artifact_enabled: bool,
) -> str:
    repo_verdict = report.get("repo_verdict", {})
    baseline_diff = report.get("baseline_diff", {})
    queue = report.get("agent_routing_queue", [])
    hotspots = report.get("hotspots", [])
    new_count, worsened_count, resolved_count = _baseline_counts(baseline_diff)

    lines = [
        COMMENT_MARKER,
        "## Cremona report",
        "",
        f"- Debt status: {_code(_bool_label(repo_verdict.get('debt_status', 'unknown')))}",
        (
            f"- Routing pressure: "
            f"{_code(_bool_label(repo_verdict.get('routing_pressure', 'none')))}"
        ),
        f"- Signal health: {_code(_bool_label(repo_verdict.get('signal_health', 'unknown')))}",
    ]
    missing_signals = list(repo_verdict.get("missing_signals", []))
    if missing_signals:
        lines.append("- Missing signals: " + ", ".join(_code(signal) for signal in missing_signals))
    lines.extend(
        [
            (
                f"- Baseline regressions: "
                f"{_code(_bool_label(baseline_diff.get('has_regressions', False)))}"
            ),
            (
                f"- Baseline diff: "
                f"{_code(f'new={new_count}')}, "
                f"{_code(f'worsened={worsened_count}')}, "
                f"{_code(f'resolved={resolved_count}')}"
            ),
            "",
            *_render_routing_lines(queue, max_comment_rows=max_comment_rows),
            "",
            *_render_hotspot_lines(hotspots, max_hotspots=max_hotspots),
            "",
            _render_footer(
                artifact_name=artifact_name,
                artifact_enabled=artifact_enabled,
            ),
            "",
        ]
    )
    return "\n".join(lines)


def render_pr_comment_from_path(
    report_json_path: Path,
    *,
    max_comment_rows: int,
    max_hotspots: int,
    artifact_name: str,
    artifact_enabled: bool,
) -> str:
    try:
        report = json.loads(report_json_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return render_fallback_comment()
    return render_pr_comment(
        report,
        max_comment_rows=max_comment_rows,
        max_hotspots=max_hotspots,
        artifact_name=artifact_name,
        artifact_enabled=artifact_enabled,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m cremona.pr_comment")
    parser.add_argument(
        "--report-json",
        type=Path,
        default=Path("output/refactor-audit/report.json"),
        help="Path to report.json.",
    )
    parser.add_argument(
        "--max-comment-rows",
        type=int,
        default=5,
        help="Maximum routing rows to include in the PR comment.",
    )
    parser.add_argument(
        "--max-hotspots",
        type=int,
        default=3,
        help="Maximum hotspots to include in the PR comment.",
    )
    parser.add_argument(
        "--artifact-name",
        default="cremona-report",
        help="Artifact name mentioned in the footer when artifact upload is enabled.",
    )
    parser.add_argument(
        "--artifact-enabled",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Whether the workflow uploads the report artifact.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    markdown = render_pr_comment_from_path(
        args.report_json,
        max_comment_rows=args.max_comment_rows,
        max_hotspots=args.max_hotspots,
        artifact_name=args.artifact_name,
        artifact_enabled=args.artifact_enabled,
    )
    print(markdown, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
