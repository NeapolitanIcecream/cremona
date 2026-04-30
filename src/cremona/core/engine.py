from __future__ import annotations

import argparse
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import tempfile
import time
from typing import Any, Callable, Iterable, Iterator, Mapping

from ..profiles import Profile, get_profile
from ..python_tools.engine import (
    ScopeLookup,
    collect_python_files,
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
from .baseline import (
    _baseline_report_is_supported,
    _require_supported_baseline_report,
    build_baseline_diff,
    build_baseline_snapshot,
    dead_code_regression_reasons as dead_code_regression_reasons,
    hotspot_new_item_is_regression as hotspot_new_item_is_regression,
    hotspot_regression_reasons as hotspot_regression_reasons,
    summarize_dead_code as summarize_dead_code,
    summarize_hotspot as summarize_hotspot,
)
from .models import (
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
)
from .reporting import (
    build_repo_verdict,
    build_summary,
    build_summary_from_file_count as build_summary_from_file_count,
    build_tool_summaries,
    build_tool_summaries_from_snapshot as build_tool_summaries_from_snapshot,
    format_tool_metrics as format_tool_metrics,
    render_markdown_report,
    severity_summary as severity_summary,
    severity_summary_from_levels as severity_summary_from_levels,
    write_json,
)
from .routing import (
    _unknown_coverage_summary,
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


_AUDIT_TIMING_PHASES = (
    "prepare_scope",
    "audit_tools",
    "aggregate_findings",
    "history_collection",
    "routing_queue",
    "baseline_comparison",
    "repo_verdict",
    "report_assembly",
)
_AUDIT_TIMING_TOOLS = ("ruff", "lizard", "complexipy", "vulture")


@dataclass
class _TimingDiagnostics:
    clock: Callable[[], float] = time.monotonic
    phases_ms: dict[str, float] = field(default_factory=dict)
    tools_ms: dict[str, float] = field(default_factory=dict)

    @contextmanager
    def track_phase(self, name: str) -> Iterator[None]:
        if name not in _AUDIT_TIMING_PHASES:
            raise ValueError(f"Unknown audit timing phase: {name}")
        start = self.clock()
        try:
            yield
        finally:
            self._record(self.phases_ms, name, start)

    @contextmanager
    def track_tool(self, name: str) -> Iterator[None]:
        if name not in _AUDIT_TIMING_TOOLS:
            raise ValueError(f"Unknown audit timing tool: {name}")
        start = self.clock()
        try:
            yield
        finally:
            self._record(self.tools_ms, name, start)

    def _record(self, target: dict[str, float], name: str, start: float) -> None:
        duration_ms = max((self.clock() - start) * 1000.0, 0.0)
        target[name] = round(target.get(name, 0.0) + duration_ms, 3)

    def as_payload(self) -> dict[str, Any]:
        return {
            "unit": "milliseconds",
            "phases": {
                name: {"duration_ms": self.phases_ms[name]}
                for name in _AUDIT_TIMING_PHASES
                if name in self.phases_ms
            },
            "tools": {
                name: {"duration_ms": self.tools_ms[name]}
                for name in _AUDIT_TIMING_TOOLS
                if name in self.tools_ms
            },
        }


@contextmanager
def _track_phase(
    timings: _TimingDiagnostics | None,
    name: str,
) -> Iterator[None]:
    if timings is None:
        yield
        return
    with timings.track_phase(name):
        yield


@contextmanager
def _track_tool(
    timings: _TimingDiagnostics | None,
    name: str,
) -> Iterator[None]:
    if timings is None:
        yield
        return
    with timings.track_tool(name):
        yield


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
    *,
    timings: _TimingDiagnostics | None = None,
) -> AuditToolRunResult:
    file_args = [str(path) for path in scope_state.files]
    with _track_tool(timings, "ruff"):
        ruff_signals = _run_ruff_audit(
            file_args=file_args,
            raw_dir=scope_state.raw_dir,
            lookup=scope_state.lookup,
            config=request.config,
        )
    with _track_tool(timings, "lizard"):
        lizard_signals = _run_lizard_audit(
            file_args=file_args,
            raw_dir=scope_state.raw_dir,
            lookup=scope_state.lookup,
            config=request.config,
        )
    with _track_tool(timings, "complexipy"):
        complexipy_signals = _run_complexipy_audit(
            file_args=file_args,
            raw_dir=scope_state.raw_dir,
            lookup=scope_state.lookup,
            config=request.config,
        )
    with _track_tool(timings, "vulture"):
        dead_code_candidates = _run_vulture_audit(
            file_args=file_args,
            raw_dir=scope_state.raw_dir,
            lookup=scope_state.lookup,
            config=request.config,
        )
    return AuditToolRunResult(
        ruff_signals=ruff_signals,
        lizard_signals=lizard_signals,
        complexipy_signals=complexipy_signals,
        dead_code_candidates=dead_code_candidates,
    )


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
    timings: _TimingDiagnostics | None = None,
) -> _AuditExecutionResult:
    with _track_phase(timings, "aggregate_findings"):
        hotspots, tool_summaries = _build_hotspots_and_tool_summaries(
            tool_run=tool_run,
            config=request.config,
        )
    with _track_phase(timings, "history_collection"):
        history_summary = _collect_history_summary_for_scope(
            request=request,
            scope_state=scope_state,
        )
    with _track_phase(timings, "routing_queue"):
        agent_routing_queue = _build_agent_routing_queue_for_scope(
            request=request,
            scope_state=scope_state,
            hotspots=hotspots,
            dead_code_candidates=tool_run.dead_code_candidates,
            history_summary=history_summary,
        )
    with _track_phase(timings, "baseline_comparison"):
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
    with _track_phase(timings, "repo_verdict"):
        repo_verdict = build_repo_verdict(
            hotspots=hotspots,
            baseline_diff=baseline_diff,
            agent_routing_queue=agent_routing_queue,
            history_summary=history_summary,
        )
    with _track_phase(timings, "report_assembly"):
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
        timings = _TimingDiagnostics()
        with _track_phase(timings, "prepare_scope"):
            scope_state = _prepare_audit_scope(resolved_request)
        with _track_phase(timings, "audit_tools"):
            tool_run = _run_audit_tools(
                scope_state,
                resolved_request,
                timings=timings,
            )
        execution = _execute_refactor_audit(
            request=resolved_request,
            scope_state=scope_state,
            tool_run=tool_run,
            timings=timings,
        )
        execution.report["diagnostics"] = {"timings": timings.as_payload()}
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
