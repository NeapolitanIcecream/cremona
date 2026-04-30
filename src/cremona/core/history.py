from __future__ import annotations

import subprocess
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from ..python_tools.engine import run_command

__all__ = [
    "build_history_summary",
    "collect_git_history_summary",
]

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class _GitHistoryCollectionRequest:
    repo_root: Path
    targets: tuple[str, ...]
    tracked_files: tuple[str, ...]
    current_scope_files: tuple[str, ...]
    lookback_days: int
    min_shared_commits: int
    coupling_ignore_commit_file_count: int
    raw_path: Path | None = None


@dataclass
class _HistoryAggregationState:
    commit_frequency: Counter[str]
    churn: Counter[str]
    coupling: dict[str, Counter[str]]
    files_in_commit: set[str]


def _empty_history_file_summary() -> dict[str, Any]:
    return {
        "commit_frequency": 0,
        "churn": 0,
        "top_coupled_files": [],
    }


def _empty_history_summary(
    *,
    current_scope_files: Iterable[str],
    lookback_days: int,
    status: Literal["available", "unavailable"],
) -> dict[str, Any]:
    return {
        "status": status,
        "lookback_days": lookback_days,
        "max_commit_frequency": 0,
        "max_churn": 0,
        "files": {
            file: _empty_history_file_summary()
            for file in sorted(set(current_scope_files))
        },
    }


def _finalize_commit_coupling(
    *,
    state: _HistoryAggregationState,
    coupling_ignore_commit_file_count: int,
) -> None:
    file_list = sorted(state.files_in_commit)
    if (
        coupling_ignore_commit_file_count > 0
        and len(file_list) > coupling_ignore_commit_file_count
    ):
        return
    for index, file_name in enumerate(file_list):
        for other in file_list[index + 1 :]:
            state.coupling[file_name][other] += 1
            state.coupling[other][file_name] += 1


def _parse_git_numstat_line(raw_line: str) -> tuple[int, int, str] | None:
    if not raw_line.strip():
        return None
    parts = raw_line.split("\t")
    if len(parts) != 3:
        return None
    added, removed, path = parts
    if added == "-" or removed == "-":
        return None
    try:
        return (int(added), int(removed), path)
    except ValueError:
        return None


def _record_history_entry(
    *,
    entry: tuple[int, int, str],
    tracked_file_set: set[str],
    state: _HistoryAggregationState,
) -> None:
    added_count, removed_count, path = entry
    if path not in tracked_file_set:
        return
    state.commit_frequency[path] += 1
    state.churn[path] += added_count + removed_count
    state.files_in_commit.add(path)


def _coupled_history_files(
    *,
    file_name: str,
    coupling: dict[str, Counter[str]],
    current_scope_set: set[str],
    min_shared_commits: int,
) -> list[dict[str, Any]]:
    return [
        {
            "file": other,
            "shared_commits": shared_commits,
            "in_scope": other in current_scope_set,
        }
        for other, shared_commits in sorted(
            coupling.get(file_name, {}).items(),
            key=lambda item: (-item[1], item[0]),
        )
        if shared_commits >= min_shared_commits
    ]


def _build_history_files_summary(
    *,
    current_scope: tuple[str, ...],
    current_scope_set: set[str],
    tracked_file_set: set[str],
    state: _HistoryAggregationState,
    min_shared_commits: int,
) -> tuple[int, int, dict[str, Any]]:
    max_commit_frequency = max(
        (state.commit_frequency[file_name] for file_name in tracked_file_set),
        default=0,
    )
    max_churn = max(
        (state.churn[file_name] for file_name in tracked_file_set),
        default=0,
    )
    files = {
        file_name: {
            "commit_frequency": int(state.commit_frequency.get(file_name, 0)),
            "churn": int(state.churn.get(file_name, 0)),
            "top_coupled_files": _coupled_history_files(
                file_name=file_name,
                coupling=state.coupling,
                current_scope_set=current_scope_set,
                min_shared_commits=min_shared_commits,
            ),
        }
        for file_name in current_scope
    }
    return (int(max_commit_frequency), int(max_churn), files)


def build_history_summary(
    *,
    raw_text: str,
    tracked_files: Iterable[str],
    current_scope_files: Iterable[str],
    min_shared_commits: int,
    coupling_ignore_commit_file_count: int,
    lookback_days: int,
) -> dict[str, Any]:
    tracked_file_set = set(tracked_files)
    current_scope = tuple(sorted(set(current_scope_files)))
    current_scope_set = set(current_scope)
    state = _HistoryAggregationState(
        commit_frequency=Counter(),
        churn=Counter(),
        coupling=defaultdict(Counter),
        files_in_commit=set(),
    )

    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if raw_line.startswith("commit "):
            _finalize_commit_coupling(
                state=state,
                coupling_ignore_commit_file_count=coupling_ignore_commit_file_count,
            )
            state.files_in_commit = set()
            continue
        if not line:
            continue
        parsed_entry = _parse_git_numstat_line(raw_line)
        if parsed_entry is None:
            continue
        _record_history_entry(
            entry=parsed_entry,
            tracked_file_set=tracked_file_set,
            state=state,
        )
    _finalize_commit_coupling(
        state=state,
        coupling_ignore_commit_file_count=coupling_ignore_commit_file_count,
    )
    max_commit_frequency, max_churn, files = _build_history_files_summary(
        current_scope=current_scope,
        current_scope_set=current_scope_set,
        tracked_file_set=tracked_file_set,
        state=state,
        min_shared_commits=min_shared_commits,
    )
    return {
        "status": "available",
        "lookback_days": lookback_days,
        "max_commit_frequency": max_commit_frequency,
        "max_churn": max_churn,
        "files": files,
    }


def _coerce_git_history_collection_request(
    *,
    request: _GitHistoryCollectionRequest | None = None,
    legacy_kwargs: dict[str, Any] | None = None,
) -> _GitHistoryCollectionRequest:
    if request is not None:
        return request
    values = dict(legacy_kwargs or {})
    return _GitHistoryCollectionRequest(
        repo_root=values["repo_root"],
        targets=tuple(values["targets"]),
        tracked_files=tuple(values["tracked_files"]),
        current_scope_files=tuple(values["current_scope_files"]),
        lookback_days=int(values["lookback_days"]),
        min_shared_commits=int(values["min_shared_commits"]),
        coupling_ignore_commit_file_count=int(
            values["coupling_ignore_commit_file_count"]
        ),
        raw_path=values.get("raw_path"),
    )


def collect_git_history_summary(
    request: _GitHistoryCollectionRequest | None = None,
    *,
    command_runner: CommandRunner | None = None,
    **legacy_kwargs: Any,
) -> dict[str, Any]:
    resolved_request = _coerce_git_history_collection_request(
        request=request,
        legacy_kwargs=legacy_kwargs,
    )
    tracked_file_set = set(resolved_request.tracked_files)
    if not tracked_file_set:
        return _empty_history_summary(
            current_scope_files=resolved_request.current_scope_files,
            lookback_days=resolved_request.lookback_days,
            status="unavailable",
        )
    since = (
        datetime.now(UTC) - timedelta(days=resolved_request.lookback_days)
    ).date().isoformat()
    if command_runner is None:
        command_runner = run_command
    try:
        completed = command_runner(
            command=[
                "git",
                "log",
                f"--since={since}",
                "--numstat",
                "--format=commit %H",
                "--",
                *resolved_request.targets,
            ],
            cwd=resolved_request.repo_root,
            allowed_returncodes={0},
        )
    except RuntimeError:
        if resolved_request.raw_path is not None:
            resolved_request.raw_path.write_text("", encoding="utf-8")
        return _empty_history_summary(
            current_scope_files=resolved_request.current_scope_files,
            lookback_days=resolved_request.lookback_days,
            status="unavailable",
        )
    if resolved_request.raw_path is not None:
        resolved_request.raw_path.write_text(completed.stdout, encoding="utf-8")
    return build_history_summary(
        raw_text=completed.stdout,
        tracked_files=tracked_file_set,
        current_scope_files=resolved_request.current_scope_files,
        min_shared_commits=resolved_request.min_shared_commits,
        coupling_ignore_commit_file_count=resolved_request.coupling_ignore_commit_file_count,
        lookback_days=resolved_request.lookback_days,
    )
