from __future__ import annotations

import argparse
import ast
import csv
import fnmatch
import json
import os
import re
import subprocess
import tempfile
import tomllib
from collections import Counter, defaultdict
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterable, Literal, cast

from .profiles import DEFAULT_PROFILE, Profile, empty_ambiguity_signals, get_profile

REPO_ROOT = Path.cwd()
SCHEMA_VERSION = 2
HOTSPOT_CLASSIFICATIONS = ("monitor", "refactor_soon", "refactor_now")
HOTSPOT_CLASSIFICATION_RANK = {
    "monitor": 1,
    "refactor_soon": 2,
    "refactor_now": 3,
}
SEVERITY_RANK = {
    "warning": 1,
    "high": 2,
    "critical": 3,
}
AGENT_PRIORITY_BAND_RANK = {
    "watch": 1,
    "investigate_soon": 2,
    "investigate_now": 3,
}
QUEUE_ORDER = tuple(DEFAULT_PROFILE.queue_order)
_ACTIVE_PROFILE = DEFAULT_PROFILE
_VULTURE_IGNORED_DECORATORS = frozenset(
    {
        "field_validator",
        "model_validator",
        "field_serializer",
        "model_serializer",
    }
)


@dataclass(frozen=True)
class MetricBands:
    warning_min: int
    warning_max: int
    high_min: int
    high_max: int
    critical_min: int

    def classify(self, value: int) -> Literal["warning", "high", "critical"] | None:
        if value >= self.critical_min:
            return "critical"
        if self.high_min <= value <= self.high_max:
            return "high"
        if self.warning_min <= value <= self.warning_max:
            return "warning"
        return None


@dataclass(frozen=True)
class LizardBands:
    ccn: MetricBands
    nloc: MetricBands
    parameter_count: MetricBands


@dataclass(frozen=True)
class VultureBands:
    review_candidate_min: int
    high_confidence_candidate_min: int

    def classify(
        self, confidence: int
    ) -> Literal["review_candidate", "high_confidence_candidate"] | None:
        if confidence >= self.high_confidence_candidate_min:
            return "high_confidence_candidate"
        if confidence >= self.review_candidate_min:
            return "review_candidate"
        return None


@dataclass(frozen=True)
class HistoryConfig:
    lookback_days: int
    min_shared_commits: int
    coupling_ignore_commit_file_count: int


@dataclass(frozen=True)
class CoverageConfig:
    coverage_json: Path | None


@dataclass(frozen=True)
class AuditConfig:
    repo_root: Path
    profile: str
    targets: tuple[str, ...]
    exclude: tuple[str, ...]
    out_dir: Path
    baseline: Path
    ruff: MetricBands
    lizard: LizardBands
    complexipy: MetricBands
    vulture: VultureBands
    history: HistoryConfig
    coverage: CoverageConfig


@dataclass(frozen=True)
class ScopeLookup:
    repo_root: Path
    allowed_rel_paths: frozenset[str]
    rel_paths_by_basename: dict[str, tuple[str, ...]]
    qualified_names_by_path: dict[str, frozenset[str]]
    qualified_names_by_path_and_leaf: dict[str, dict[str, tuple[str, ...]]]
    qualified_names_by_path_and_line: dict[str, dict[int, str]]
    vulture_ignored_lines_by_path: dict[str, frozenset[int]]

    @classmethod
    def from_files(cls, *, repo_root: Path, files: list[Path]) -> ScopeLookup:
        rel_paths = [relative_path(path, repo_root) for path in files]
        grouped: dict[str, list[str]] = defaultdict(list)
        qualified_names_by_path: dict[str, frozenset[str]] = {}
        qualified_names_by_path_and_leaf: dict[str, dict[str, tuple[str, ...]]] = {}
        qualified_names_by_path_and_line: dict[str, dict[int, str]] = {}
        vulture_ignored_lines_by_path: dict[str, frozenset[int]] = {}
        for rel_path in rel_paths:
            grouped[Path(rel_path).name].append(rel_path)
            path = repo_root / rel_path
            symbol_index = build_symbol_index(path)
            qualified_names_by_path[rel_path] = frozenset(
                symbol_index["qualified_names"]
            )
            qualified_names_by_path_and_leaf[rel_path] = symbol_index["by_leaf"]
            qualified_names_by_path_and_line[rel_path] = symbol_index["by_line"]
            vulture_ignored_lines_by_path[rel_path] = frozenset(
                symbol_index["vulture_ignored_lines"]
            )
        rel_paths_by_basename = {
            name: tuple(sorted(values)) for name, values in grouped.items()
        }
        return cls(
            repo_root=repo_root,
            allowed_rel_paths=frozenset(rel_paths),
            rel_paths_by_basename=rel_paths_by_basename,
            qualified_names_by_path=qualified_names_by_path,
            qualified_names_by_path_and_leaf=qualified_names_by_path_and_leaf,
            qualified_names_by_path_and_line=qualified_names_by_path_and_line,
            vulture_ignored_lines_by_path=vulture_ignored_lines_by_path,
        )


@dataclass(frozen=True)
class RefactorAuditRunRequest:
    scope_targets: list[str]
    out_dir: Path
    baseline_path: Path
    update_baseline: bool
    fail_on_regression: bool
    lookback_days: int
    coverage_json: Path | None
    config: AuditConfig


@dataclass(frozen=True)
class HotspotSignal:
    tool: Literal["ruff", "lizard", "complexipy"]
    file: str
    symbol: str
    line: int | None
    severity: Literal["warning", "high", "critical"]
    metrics: dict[str, int]
    message: str

    @property
    def symbol_key(self) -> str:
        return f"{self.file}::{normalize_symbol_key(self.symbol)}"


@dataclass(frozen=True)
class AuditScopeState:
    files: list[Path]
    current_scope_files: list[str]
    default_scope_files: tuple[str, ...]
    is_partial_scope: bool
    lookup: ScopeLookup
    raw_dir: Path


@dataclass(frozen=True)
class AuditToolRunResult:
    ruff_signals: list[HotspotSignal]
    lizard_signals: list[HotspotSignal]
    complexipy_signals: list[HotspotSignal]
    dead_code_candidates: list[dict[str, Any]]


@dataclass(frozen=True)
class RoutingFileContext:
    file_name: str
    history_entry: dict[str, Any]
    coverage_entry: dict[str, Any]
    ambiguity_signals: dict[str, int]
    file_hotspots: list[dict[str, Any]]
    file_dead_code: list[dict[str, Any]]
    max_commit_frequency: int
    max_churn: int


@dataclass(frozen=True)
class _DiffRegressionContext:
    current_items_by_id: dict[str, dict[str, Any]]
    baseline_items_by_id: dict[str, dict[str, Any]]
    kind: str
    summarize: Callable[[dict[str, Any]], dict[str, Any]]
    new_item_is_regression: Callable[[dict[str, Any]], bool]
    regression_reasons: Callable[[dict[str, Any], dict[str, Any]], list[str]]


@dataclass(frozen=True)
class _AuditReportContext:
    request: RefactorAuditRunRequest
    scope_state: AuditScopeState
    hotspots: list[dict[str, Any]]
    dead_code_candidates: list[dict[str, Any]]
    agent_routing_queue: list[dict[str, Any]]
    history_summary: dict[str, Any]
    tool_summaries: dict[str, dict[str, Any]]
    baseline_diff: dict[str, Any]
    repo_verdict: dict[str, Any]


@dataclass(frozen=True)
class ScanRequest:
    scope_targets: list[str]
    out_dir: Path
    baseline_path: Path
    update_baseline: bool = False
    fail_on_regression: bool = False
    lookback_days: int | None = None
    coverage_json: Path | None = None
    config: AuditConfig | None = None
    profile: str | Profile | None = None


@dataclass(frozen=True)
class ScanReport(Mapping[str, Any]):
    payload: dict[str, Any]
    exit_code: int = 0

    def __getitem__(self, key: str) -> Any:
        return self.payload[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.payload)

    def __len__(self) -> int:
        return len(self.payload)

    def to_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def _set_active_profile(profile: Profile) -> Profile:
    global _ACTIVE_PROFILE
    global QUEUE_ORDER
    previous = _ACTIVE_PROFILE
    _ACTIVE_PROFILE = profile
    QUEUE_ORDER = tuple(profile.queue_order)
    return previous


def load_audit_config(*, repo_root: Path = REPO_ROOT) -> AuditConfig:
    pyproject_path = repo_root / "pyproject.toml"
    defaults: dict[str, Any] = {
        "profile": DEFAULT_PROFILE.name,
        "targets": ["."],
        "exclude": [
            ".git",
            ".venv",
            ".pytest_cache",
            ".ruff_cache",
            ".pyright",
            "*/__pycache__/*",
        ],
        "out_dir": "output/refactor-audit",
        "baseline": "quality/refactor-baseline.json",
        "ruff": {
            "warning_min": 11,
            "warning_max": 15,
            "high_min": 16,
            "high_max": 24,
            "critical_min": 25,
        },
        "lizard": {
            "ccn_warning_min": 15,
            "ccn_warning_max": 19,
            "ccn_high_min": 20,
            "ccn_high_max": 29,
            "ccn_critical_min": 30,
            "nloc_warning_min": 80,
            "nloc_warning_max": 119,
            "nloc_high_min": 120,
            "nloc_high_max": 149,
            "nloc_critical_min": 150,
            "parameter_warning_min": 6,
            "parameter_warning_max": 7,
            "parameter_high_min": 8,
            "parameter_high_max": 8,
            "parameter_critical_min": 9,
        },
        "complexipy": {
            "warning_min": 16,
            "warning_max": 29,
            "high_min": 30,
            "high_max": 49,
            "critical_min": 50,
        },
        "vulture": {
            "review_candidate_min": 60,
            "high_confidence_candidate_min": 80,
        },
        "history": {
            "lookback_days": 180,
            "min_shared_commits": 3,
            "coupling_ignore_commit_file_count": 25,
        },
        "coverage": {
            "coverage_json": "",
        },
    }
    config_data = dict(defaults)
    if pyproject_path.exists():
        data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
        loaded = data.get("tool", {}).get("cremona", {})
        if isinstance(loaded, dict):
            for key, value in loaded.items():
                if isinstance(value, dict) and isinstance(config_data.get(key), dict):
                    merged = dict(config_data[key])
                    merged.update(value)
                    config_data[key] = merged
                else:
                    config_data[key] = value
    return AuditConfig(
        repo_root=repo_root,
        profile=str(config_data.get("profile") or DEFAULT_PROFILE.name),
        targets=tuple(config_data["targets"]),
        exclude=tuple(config_data["exclude"]),
        out_dir=resolve_repo_path(repo_root, str(config_data["out_dir"])),
        baseline=resolve_repo_path(repo_root, str(config_data["baseline"])),
        ruff=_metric_bands(config_data["ruff"]),
        lizard=LizardBands(
            ccn=MetricBands(
                warning_min=int(config_data["lizard"]["ccn_warning_min"]),
                warning_max=int(config_data["lizard"]["ccn_warning_max"]),
                high_min=int(config_data["lizard"]["ccn_high_min"]),
                high_max=int(config_data["lizard"]["ccn_high_max"]),
                critical_min=int(config_data["lizard"]["ccn_critical_min"]),
            ),
            nloc=MetricBands(
                warning_min=int(config_data["lizard"]["nloc_warning_min"]),
                warning_max=int(config_data["lizard"]["nloc_warning_max"]),
                high_min=int(config_data["lizard"]["nloc_high_min"]),
                high_max=int(config_data["lizard"]["nloc_high_max"]),
                critical_min=int(config_data["lizard"]["nloc_critical_min"]),
            ),
            parameter_count=MetricBands(
                warning_min=int(config_data["lizard"]["parameter_warning_min"]),
                warning_max=int(config_data["lizard"]["parameter_warning_max"]),
                high_min=int(config_data["lizard"]["parameter_high_min"]),
                high_max=int(config_data["lizard"]["parameter_high_max"]),
                critical_min=int(config_data["lizard"]["parameter_critical_min"]),
            ),
        ),
        complexipy=_metric_bands(config_data["complexipy"]),
        vulture=VultureBands(
            review_candidate_min=int(config_data["vulture"]["review_candidate_min"]),
            high_confidence_candidate_min=int(
                config_data["vulture"]["high_confidence_candidate_min"]
            ),
        ),
        history=HistoryConfig(
            lookback_days=int(config_data["history"]["lookback_days"]),
            min_shared_commits=int(config_data["history"]["min_shared_commits"]),
            coupling_ignore_commit_file_count=int(
                config_data["history"]["coupling_ignore_commit_file_count"]
            ),
        ),
        coverage=CoverageConfig(
            coverage_json=(
                None
                if not str(config_data["coverage"].get("coverage_json") or "").strip()
                else resolve_repo_path(
                    repo_root, str(config_data["coverage"]["coverage_json"])
                )
            )
        ),
    )


def _metric_bands(values: dict[str, Any]) -> MetricBands:
    return MetricBands(
        warning_min=int(values["warning_min"]),
        warning_max=int(values["warning_max"]),
        high_min=int(values["high_min"]),
        high_max=int(values["high_max"]),
        critical_min=int(values["critical_min"]),
    )


def resolve_repo_path(repo_root: Path, value: str) -> Path:
    candidate = Path(value)
    if candidate.is_absolute():
        return candidate
    return (repo_root / candidate).resolve()


def relative_path(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return Path(os.path.relpath(path.resolve(), repo_root.resolve())).as_posix()


def is_excluded(*, path: Path, repo_root: Path, patterns: tuple[str, ...]) -> bool:
    rel_path = relative_path(path, repo_root)
    rel_parts = Path(rel_path).parts
    for pattern in patterns:
        normalized = pattern.rstrip("/")
        if not normalized:
            continue
        if fnmatch.fnmatch(rel_path, normalized):
            return True
        if fnmatch.fnmatch(path.name, normalized):
            return True
        if normalized in rel_parts:
            return True
        if rel_path.startswith(f"{normalized}/"):
            return True
    return False


def collect_python_files(
    *, repo_root: Path, targets: list[str], exclude_patterns: tuple[str, ...]
) -> list[Path]:
    files: dict[str, Path] = {}
    for target in targets:
        candidate = Path(target)
        resolved = candidate if candidate.is_absolute() else (repo_root / candidate)
        resolved = resolved.resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"Scope target does not exist: {target}")
        if is_excluded(path=resolved, repo_root=repo_root, patterns=exclude_patterns):
            continue
        if resolved.is_file():
            if resolved.suffix == ".py":
                files[relative_path(resolved, repo_root)] = resolved
            continue
        for path in resolved.rglob("*.py"):
            if is_excluded(path=path, repo_root=repo_root, patterns=exclude_patterns):
                continue
            files[relative_path(path, repo_root)] = path.resolve()
    return [files[key] for key in sorted(files)]


def resolve_reported_path(reported: str, lookup: ScopeLookup) -> str | None:
    reported_path = Path(str(reported))
    if reported_path.is_absolute():
        rel_path = relative_path(reported_path, lookup.repo_root)
        return rel_path if rel_path in lookup.allowed_rel_paths else None
    rel_candidate = reported_path.as_posix()
    if rel_candidate in lookup.allowed_rel_paths:
        return rel_candidate
    basename_matches = lookup.rel_paths_by_basename.get(reported_path.name, ())
    if len(basename_matches) == 1:
        return basename_matches[0]
    repo_candidate = relative_path(lookup.repo_root / reported_path, lookup.repo_root)
    if repo_candidate in lookup.allowed_rel_paths:
        return repo_candidate
    return None


@dataclass
class _SymbolIndexBuffers:
    qualified_names: list[str]
    by_leaf: dict[str, list[str]]
    by_line: dict[int, str]
    vulture_ignored_lines: set[int]


def build_symbol_index(path: Path) -> dict[str, Any]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    buffers = _SymbolIndexBuffers(
        qualified_names=[],
        by_leaf=defaultdict(list),
        by_line={},
        vulture_ignored_lines=set(),
    )

    def walk(node: ast.AST, prefix: str = "", parent_kind: str | None = None) -> None:
        body = getattr(node, "body", None)
        if not isinstance(body, list):
            return
        for child in body:
            if isinstance(child, ast.ClassDef):
                qualified = _qualified_symbol_name(
                    prefix=prefix,
                    parent_kind=parent_kind,
                    child_name=child.name,
                    child_kind="class",
                )
                walk(child, qualified, "class")
                continue
            if isinstance(child, ast.AsyncFunctionDef | ast.FunctionDef):
                qualified = _qualified_symbol_name(
                    prefix=prefix,
                    parent_kind=parent_kind,
                    child_name=child.name,
                    child_kind="function",
                )
                _record_function_symbol(
                    node=child,
                    qualified=qualified,
                    buffers=buffers,
                )
                walk(child, qualified, "function")

    walk(tree)
    return {
        "qualified_names": tuple(sorted(buffers.qualified_names)),
        "by_leaf": {
            leaf: tuple(sorted(values))
            for leaf, values in sorted(buffers.by_leaf.items())
        },
        "by_line": dict(sorted(buffers.by_line.items())),
        "vulture_ignored_lines": tuple(sorted(buffers.vulture_ignored_lines)),
    }


def _qualified_symbol_name(
    *,
    prefix: str,
    parent_kind: str | None,
    child_name: str,
    child_kind: Literal["class", "function"],
) -> str:
    if not prefix:
        return child_name
    if child_kind == "class" or parent_kind == "class":
        return f"{prefix}::{child_name}"
    return f"{prefix}.{child_name}"


def _record_function_symbol(
    *,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    qualified: str,
    buffers: _SymbolIndexBuffers,
) -> None:
    buffers.qualified_names.append(qualified)
    buffers.by_line[int(node.lineno)] = qualified
    buffers.by_leaf[node.name].append(qualified)
    if _has_vulture_ignored_decorator(node):
        buffers.vulture_ignored_lines.update(_vulture_ignored_line_span(node))


def _has_vulture_ignored_decorator(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    return any(
        _decorator_base_name(decorator) in _VULTURE_IGNORED_DECORATORS
        for decorator in node.decorator_list
    )


def _decorator_base_name(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        return _decorator_base_name(node.func)
    if isinstance(node, ast.Name):
        return str(node.id)
    if isinstance(node, ast.Attribute):
        return str(node.attr)
    return ""


def _vulture_ignored_line_span(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[int]:
    if not node.decorator_list:
        return {int(node.lineno)}
    start_line = min(
        int(getattr(decorator, "lineno", node.lineno))
        for decorator in node.decorator_list
    )
    end_line = int(node.lineno)
    return set(range(start_line, end_line + 1))


def normalize_symbol_key(symbol: str) -> str:
    cleaned = str(symbol).strip().replace(" ", "")
    if not cleaned:
        return "unknown"
    return cleaned


def optional_int(value: object) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return int(value)
        except ValueError:
            return None
    return None


def resolve_canonical_symbol(
    *, rel_path: str, symbol: str, line: int | None, lookup: ScopeLookup
) -> str:
    cleaned = str(symbol).strip()
    if not cleaned:
        return "unknown"
    by_line = lookup.qualified_names_by_path_and_line.get(rel_path, {})
    if line is not None and line in by_line:
        return by_line[line]
    qualified_names = lookup.qualified_names_by_path.get(rel_path, frozenset())
    if cleaned in qualified_names:
        return cleaned
    leaf = cleaned.split("::")[-1].split(".")[-1]
    matches = lookup.qualified_names_by_path_and_leaf.get(rel_path, {}).get(leaf, ())
    if len(matches) == 1:
        return matches[0]
    return cleaned


def run_command(
    command: list[str], *, cwd: Path, allowed_returncodes: set[int]
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"Command not found: {command[0]}") from exc
    if completed.returncode not in allowed_returncodes:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(
            f"Command failed with exit code {completed.returncode}: {' '.join(command)}"
            + (f"\n{detail}" if detail else "")
        )
    return completed


def parse_ruff_findings(
    *, raw_text: str, lookup: ScopeLookup, config: AuditConfig
) -> list[HotspotSignal]:
    findings: list[HotspotSignal] = []
    payload = json.loads(raw_text or "[]")
    for item in payload:
        if item.get("code") != "C901":
            continue
        message = str(item.get("message", ""))
        match = re.search(r"\((\d+)\s*>\s*\d+\)", message)
        if match is None:
            continue
        complexity = int(match.group(1))
        severity = config.ruff.classify(complexity)
        if severity is None:
            continue
        rel_path = resolve_reported_path(str(item.get("filename", "")), lookup)
        if rel_path is None:
            continue
        symbol_match = re.search(r"`([^`]+)`", message)
        symbol = symbol_match.group(1) if symbol_match else "<unknown>"
        location = item.get("location") or {}
        row = optional_int(location.get("row"))
        findings.append(
            HotspotSignal(
                tool="ruff",
                file=rel_path,
                symbol=resolve_canonical_symbol(
                    rel_path=rel_path,
                    symbol=symbol,
                    line=row,
                    lookup=lookup,
                ),
                line=row,
                severity=severity,
                metrics={"complexity": complexity},
                message=message,
            )
        )
    return findings


def parse_lizard_findings(
    *, raw_text: str, lookup: ScopeLookup, config: AuditConfig
) -> list[HotspotSignal]:
    findings: list[HotspotSignal] = []
    rows = csv.reader(raw_text.splitlines())
    for row in rows:
        if len(row) != 11:
            continue
        try:
            nloc = int(row[0])
            ccn = int(row[1])
            parameter_count = int(row[3])
            start_line = int(row[9])
        except ValueError:
            continue
        rel_path = resolve_reported_path(row[6], lookup)
        if rel_path is None:
            continue
        severities = {
            "ccn": config.lizard.ccn.classify(ccn),
            "nloc": config.lizard.nloc.classify(nloc),
            "parameter_count": config.lizard.parameter_count.classify(parameter_count),
        }
        ranked = [value for value in severities.values() if value is not None]
        if not ranked:
            continue
        severity = cast(
            Literal["warning", "high", "critical"],
            max(ranked, key=lambda value: SEVERITY_RANK[value]),
        )
        findings.append(
            HotspotSignal(
                tool="lizard",
                file=rel_path,
                symbol=resolve_canonical_symbol(
                    rel_path=rel_path,
                    symbol=row[7],
                    line=start_line,
                    lookup=lookup,
                ),
                line=start_line,
                severity=severity,
                metrics={
                    "ccn": ccn,
                    "nloc": nloc,
                    "parameter_count": parameter_count,
                    "length": int(row[4]),
                    "token_count": int(row[2]),
                },
                message=(
                    f"CCN={ccn}, NLOC={nloc}, parameter_count={parameter_count}, "
                    f"length={row[4]}"
                ),
            )
        )
    return findings


def parse_complexipy_findings(
    *, raw_text: str, lookup: ScopeLookup, config: AuditConfig
) -> list[HotspotSignal]:
    findings: list[HotspotSignal] = []
    payload = json.loads(raw_text or "[]")
    for item in payload:
        complexity = int(item["complexity"])
        severity = config.complexipy.classify(complexity)
        if severity is None:
            continue
        rel_path = resolve_reported_path(
            str(item.get("path") or item.get("file_name")), lookup
        )
        if rel_path is None:
            continue
        symbol = str(item.get("function_name") or "<unknown>")
        findings.append(
            HotspotSignal(
                tool="complexipy",
                file=rel_path,
                symbol=resolve_canonical_symbol(
                    rel_path=rel_path,
                    symbol=symbol,
                    line=None,
                    lookup=lookup,
                ),
                line=None,
                severity=severity,
                metrics={"complexity": complexity},
                message=f"cognitive complexity={complexity}",
            )
        )
    return findings


def parse_vulture_candidates(
    *, raw_text: str, lookup: ScopeLookup, config: AuditConfig
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    pattern = re.compile(
        r"^(?P<path>.+?):(?P<line>\d+): unused (?P<kind>\w+) "
        r"'(?P<symbol>.+?)' \((?P<confidence>\d+)% confidence(?:, (?P<size>\d+) lines?)?\)$"
    )
    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = pattern.match(line)
        if match is None:
            continue
        confidence = int(match.group("confidence"))
        severity = config.vulture.classify(confidence)
        if severity is None:
            continue
        rel_path = resolve_reported_path(match.group("path"), lookup)
        if rel_path is None:
            continue
        line_number = int(match.group("line"))
        if line_number in lookup.vulture_ignored_lines_by_path.get(
            rel_path, frozenset()
        ):
            continue
        symbol = match.group("symbol")
        kind = match.group("kind")
        candidates.append(
            {
                "id": f"{rel_path}::{kind}::{symbol}",
                "file": rel_path,
                "line": line_number,
                "symbol": symbol,
                "kind": kind,
                "confidence": confidence,
                "classification": severity,
                "subsystem": infer_subsystem(rel_path),
                "size": int(match.group("size")) if match.group("size") else None,
            }
        )
    candidates.sort(key=dead_code_sort_key)
    return candidates


def dead_code_sort_key(item: dict[str, Any]) -> tuple[Any, ...]:
    return (
        0 if item["classification"] == "high_confidence_candidate" else 1,
        -int(item["confidence"]),
        item["file"],
        item["symbol"],
    )


def infer_subsystem(rel_path: str) -> str:
    return _ACTIVE_PROFILE.classify_subsystem(rel_path)


def _classify_hotspot(values: list[HotspotSignal]) -> str:
    distinct_warning_plus = {
        signal.tool for signal in values if SEVERITY_RANK[signal.severity] >= 1
    }
    distinct_high_plus = {
        signal.tool for signal in values if SEVERITY_RANK[signal.severity] >= 2
    }
    has_critical_complexity = any(
        signal.tool in {"lizard", "complexipy"} and signal.severity == "critical"
        for signal in values
    )
    if has_critical_complexity or len(distinct_high_plus) >= 2:
        return "refactor_now"
    if (
        any(signal.severity in {"high", "critical"} for signal in values)
        or len(distinct_warning_plus) >= 2
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
) -> dict[str, Any]:
    line_candidates = [signal.line for signal in values if signal.line is not None]
    return {
        "id": hotspot_id,
        "file": values[0].file,
        "symbol": max((signal.symbol for signal in values), key=len),
        "line": min(line_candidates) if line_candidates else None,
        "classification": _classify_hotspot(values),
        "subsystem": infer_subsystem(values[0].file),
        "tool_count": len({signal.tool for signal in values}),
        "tools": sorted({signal.tool for signal in values}),
        "metrics": _hotspot_metrics_by_tool(values),
        "signals": _hotspot_signal_payload(values),
    }


def aggregate_hotspots(signals: list[HotspotSignal]) -> list[dict[str, Any]]:
    grouped: dict[str, list[HotspotSignal]] = defaultdict(list)
    for signal in signals:
        grouped[signal.symbol_key].append(signal)

    hotspots = [
        _aggregate_hotspot_record(hotspot_id=hotspot_id, values=values)
        for hotspot_id, values in grouped.items()
    ]
    hotspots.sort(key=hotspot_sort_key)
    return hotspots


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
    commit_frequency: Counter[str] = Counter()
    churn: Counter[str] = Counter()
    coupling: dict[str, Counter[str]] = defaultdict(Counter)
    files_in_commit: set[str] = set()

    def finalize_commit(files: set[str]) -> None:
        file_list = sorted(files)
        if (
            coupling_ignore_commit_file_count > 0
            and len(file_list) > coupling_ignore_commit_file_count
        ):
            return
        for index, file_name in enumerate(file_list):
            for other in file_list[index + 1 :]:
                coupling[file_name][other] += 1
                coupling[other][file_name] += 1

    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if raw_line.startswith("commit "):
            finalize_commit(files_in_commit)
            files_in_commit = set()
            continue
        if not line:
            continue
        parts = raw_line.split("\t")
        if len(parts) != 3:
            continue
        added, removed, path = parts
        if path not in tracked_file_set:
            continue
        if added == "-" or removed == "-":
            continue
        try:
            added_count = int(added)
            removed_count = int(removed)
        except ValueError:
            continue
        commit_frequency[path] += 1
        churn[path] += added_count + removed_count
        files_in_commit.add(path)
    finalize_commit(files_in_commit)

    max_commit_frequency = max((commit_frequency[file] for file in tracked_file_set), default=0)
    max_churn = max((churn[file] for file in tracked_file_set), default=0)
    files: dict[str, Any] = {}
    for file_name in current_scope:
        coupled = [
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
        files[file_name] = {
            "commit_frequency": int(commit_frequency.get(file_name, 0)),
            "churn": int(churn.get(file_name, 0)),
            "top_coupled_files": coupled,
        }
    return {
        "status": "available",
        "lookback_days": lookback_days,
        "max_commit_frequency": int(max_commit_frequency),
        "max_churn": int(max_churn),
        "files": files,
    }


def collect_git_history_summary(
    *,
    repo_root: Path,
    targets: list[str],
    tracked_files: Iterable[str],
    current_scope_files: Iterable[str],
    lookback_days: int,
    min_shared_commits: int,
    coupling_ignore_commit_file_count: int,
    raw_path: Path | None = None,
) -> dict[str, Any]:
    tracked_file_set = set(tracked_files)
    if not tracked_file_set:
        return _empty_history_summary(
            current_scope_files=current_scope_files,
            lookback_days=lookback_days,
            status="unavailable",
        )
    since = (datetime.now(UTC) - timedelta(days=lookback_days)).date().isoformat()
    try:
        completed = run_command(
            command=[
                "git",
                "log",
                f"--since={since}",
                "--numstat",
                "--format=commit %H",
                "--",
                *targets,
            ],
            cwd=repo_root,
            allowed_returncodes={0},
        )
    except RuntimeError:
        if raw_path is not None:
            raw_path.write_text("", encoding="utf-8")
        return _empty_history_summary(
            current_scope_files=current_scope_files,
            lookback_days=lookback_days,
            status="unavailable",
        )
    if raw_path is not None:
        raw_path.write_text(completed.stdout, encoding="utf-8")
    return build_history_summary(
        raw_text=completed.stdout,
        tracked_files=tracked_file_set,
        current_scope_files=current_scope_files,
        min_shared_commits=min_shared_commits,
        coupling_ignore_commit_file_count=coupling_ignore_commit_file_count,
        lookback_days=lookback_days,
    )


def _unknown_coverage_summary() -> dict[str, Any]:
    return {
        "mode": "unknown",
        "fraction": None,
    }


def load_coverage_summary(
    *,
    coverage_json: Path | None,
    repo_root: Path,
    tracked_files: Iterable[str],
) -> dict[str, Any]:
    tracked_file_set = set(tracked_files)
    files = {
        file_name: _unknown_coverage_summary() for file_name in sorted(tracked_file_set)
    }
    if coverage_json is None or not coverage_json.exists():
        return {
            "status": "unavailable",
            "files": files,
        }
    payload = json.loads(coverage_json.read_text(encoding="utf-8"))
    coverage_files = payload.get("files", {})
    if not isinstance(coverage_files, dict):
        return {
            "status": "unavailable",
            "files": files,
        }
    for file_name in sorted(tracked_file_set):
        candidates = [
            file_name,
            str((repo_root / file_name).resolve()),
        ]
        entry = next(
            (
                coverage_files[candidate]
                for candidate in candidates
                if candidate in coverage_files
            ),
            None,
        )
        if not isinstance(entry, dict):
            continue
        summary = entry.get("summary", {})
        if not isinstance(summary, dict):
            continue
        covered_branches = optional_int(summary.get("covered_branches"))
        num_branches = optional_int(summary.get("num_branches"))
        if (
            covered_branches is not None
            and num_branches is not None
            and num_branches > 0
        ):
            files[file_name] = {
                "mode": "branch",
                "fraction": round(covered_branches / num_branches, 4),
            }
            continue
        covered_lines = optional_int(summary.get("covered_lines"))
        num_statements = optional_int(summary.get("num_statements"))
        if (
            covered_lines is not None
            and num_statements is not None
            and num_statements > 0
        ):
            files[file_name] = {
                "mode": "line",
                "fraction": round(covered_lines / num_statements, 4),
            }
    return {
        "status": "available",
        "files": files,
    }


def _assigns_all_symbol(node: ast.AST) -> bool:
    targets = getattr(node, "targets", None)
    if isinstance(node, ast.Assign) and isinstance(targets, list):
        return any(isinstance(target, ast.Name) and target.id == "__all__" for target in targets)
    if isinstance(node, ast.AnnAssign):
        return isinstance(node.target, ast.Name) and node.target.id == "__all__"
    return False


def _is_facade_import(node: ast.AST) -> bool:
    if isinstance(node, ast.ImportFrom):
        return ".facade" in (node.module or "")
    if isinstance(node, ast.Import):
        return any(".facade" in alias.name for alias in node.names)
    return False


def build_agent_ambiguity_index(
    *,
    repo_root: Path,
    files: list[Path],
) -> dict[str, dict[str, int]]:
    return _ACTIVE_PROFILE.build_ambiguity_index(repo_root, files)


def _empty_ambiguity_signals() -> dict[str, int]:
    return empty_ambiguity_signals()


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


def _priority_band(priority_score: int) -> Literal["watch", "investigate_soon", "investigate_now"]:
    if priority_score >= 60:
        return "investigate_now"
    if priority_score >= 35:
        return "investigate_soon"
    return "watch"


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


def _ambiguity_score(ambiguity_signals: dict[str, int]) -> tuple[int, int]:
    legacy_keyword_hits = int(ambiguity_signals["legacy_keyword_hits"])
    ambiguity_score = min(
        20,
        5 * int(ambiguity_signals["module_package_shadow"])
        + 4 * int(ambiguity_signals["wildcard_reexport"])
        + 3 * int(ambiguity_signals["facade_reexport"])
        + min(6, legacy_keyword_hits // 10)
        + 2 * int(ambiguity_signals["compat_request_wrapper"]),
    )
    return (ambiguity_score, legacy_keyword_hits)


def _compatibility_pressure_score(
    *,
    legacy_keyword_hits: int,
    ambiguity_signals: dict[str, int],
    coupling_score: int,
    change_score: int,
) -> int:
    score = 0
    if legacy_keyword_hits >= 25 and int(ambiguity_signals["compat_request_wrapper"]) > 0:
        score += 4
    if legacy_keyword_hits >= 50 and coupling_score >= 10:
        score += 3
    if legacy_keyword_hits >= 100 and change_score >= 8:
        score += 2
    return score


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


def _routing_priority_components(
    context: RoutingFileContext,
) -> dict[str, int]:
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
    ambiguity_score, legacy_keyword_hits = _ambiguity_score(context.ambiguity_signals)
    high_confidence_dead_code, review_candidate_dead_code = _count_dead_code_candidates(
        context.file_dead_code
    )
    return {
        "change_score": change_score,
        "coupling_score": coupling_score,
        "static_score": _static_score(hotspot_summary),
        "ambiguity_score": ambiguity_score,
        "compatibility_pressure_score": _compatibility_pressure_score(
            legacy_keyword_hits=legacy_keyword_hits,
            ambiguity_signals=context.ambiguity_signals,
            coupling_score=coupling_score,
            change_score=change_score,
        ),
        "dead_code_score": _dead_code_score(
            high_confidence_dead_code=high_confidence_dead_code,
            review_candidate_dead_code=review_candidate_dead_code,
        ),
        "coverage_risk_score": _coverage_risk_score(context.coverage_entry),
    }


def _build_agent_routing_item(context: RoutingFileContext) -> dict[str, Any]:
    hotspot_summary = _summarize_file_hotspots(context.file_hotspots)
    priority_components = _routing_priority_components(context)
    priority_score = min(100, sum(priority_components.values()))
    return {
        "file": context.file_name,
        "subsystem": infer_subsystem(context.file_name),
        "priority_score": priority_score,
        "priority_band": _priority_band(priority_score),
        "change_frequency": int(context.history_entry.get("commit_frequency", 0)),
        "churn": int(context.history_entry.get("churn", 0)),
        "top_coupled_files": list(context.history_entry.get("top_coupled_files", [])),
        "hotspot_summary": hotspot_summary,
        "ambiguity_signals": context.ambiguity_signals,
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
    ambiguity_index: dict[str, dict[str, int]],
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
        ambiguity_signals = dict(
            ambiguity_index.get(file_name, _empty_ambiguity_signals())
        )
        file_dead_code = dead_code_by_file.get(file_name, [])
        queue.append(
            _build_agent_routing_item(
                RoutingFileContext(
                    file_name=file_name,
                    history_entry=history_entry,
                    coverage_entry=coverage_entry,
                    ambiguity_signals=ambiguity_signals,
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


def build_recommended_queue(agent_routing_queue: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {name: [] for name in QUEUE_ORDER}
    for item in agent_routing_queue:
        grouped.setdefault(item["subsystem"], []).append(item)

    queue: list[dict[str, Any]] = []
    for subsystem in QUEUE_ORDER:
        items = sorted(grouped.get(subsystem, []), key=agent_routing_sort_key)
        queue.append(
            {
                "subsystem": subsystem,
                "investigate_now": sum(
                    1
                    for item in items
                    if item["priority_band"] == "investigate_now"
                ),
                "investigate_soon": sum(
                    1
                    for item in items
                    if item["priority_band"] == "investigate_soon"
                ),
                "watch": sum(
                    1 for item in items if item["priority_band"] == "watch"
                ),
                "top_targets": [
                    {
                        "file": item["file"],
                        "priority_band": item["priority_band"],
                        "priority_score": item["priority_score"],
                    }
                    for item in items[:5]
                ],
            }
        )
    extras = [
        subsystem
        for subsystem in grouped
        if subsystem not in QUEUE_ORDER and grouped[subsystem]
    ]
    for subsystem in sorted(extras):
        items = sorted(grouped[subsystem], key=agent_routing_sort_key)
        queue.append(
            {
                "subsystem": subsystem,
                "investigate_now": sum(
                    1
                    for item in items
                    if item["priority_band"] == "investigate_now"
                ),
                "investigate_soon": sum(
                    1
                    for item in items
                    if item["priority_band"] == "investigate_soon"
                ),
                "watch": sum(
                    1 for item in items if item["priority_band"] == "watch"
                ),
                "top_targets": [
                    {
                        "file": item["file"],
                        "priority_band": item["priority_band"],
                        "priority_score": item["priority_score"],
                    }
                    for item in items[:5]
                ],
            }
        )
    return queue


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


def build_repo_verdict(
    *,
    hotspots: list[dict[str, Any]],
    baseline_diff: dict[str, Any],
    agent_routing_queue: list[dict[str, Any]],
    history_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
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
        debt_status = "corroding"
        base_summary = "Structural debt is regressing in the current scope."
    elif current_refactor_now or current_refactor_soon:
        debt_status = "strained"
        base_summary = (
            "Existing structural debt remains, but the current scope did not regress."
        )
    else:
        debt_status = "stable"
        base_summary = "No structural debt regressions were detected in the current scope."
    routing_pressure = _routing_pressure(agent_routing_queue)
    signal_health, missing_signals = _signal_health(
        history_summary=history_summary,
        agent_routing_queue=agent_routing_queue,
    )
    summary = base_summary
    if routing_pressure in {"investigate_now", "investigate_soon"}:
        summary = f"{summary} Routing pressure is {routing_pressure}."
    if missing_signals:
        missing_label = ", ".join(missing_signals)
        summary = (
            f"{base_summary} Signal health is {signal_health}: missing {missing_label}."
        )
        if routing_pressure in {"investigate_now", "investigate_soon"}:
            summary = (
                f"{base_summary} Routing pressure is {routing_pressure}. "
                f"Signal health is {signal_health}: missing {missing_label}."
            )
    return {
        "status": debt_status,
        "debt_status": debt_status,
        "routing_pressure": routing_pressure,
        "summary": summary,
        "has_regressions": has_regressions,
        "signal_health": signal_health,
        "missing_signals": missing_signals,
        "refactor_now_total": len(current_refactor_now),
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


def build_baseline_snapshot(
    report: dict[str, Any],
    *,
    baseline_report: dict[str, Any] | None = None,
    scope_files: Iterable[str] | None = None,
) -> dict[str, Any]:
    snapshot = dict(report)
    scoped_file_set = set(scope_files or [])
    if baseline_report is not None and scoped_file_set:
        snapshot["hotspots"] = sorted(
            [
                item
                for item in baseline_report.get("hotspots", [])
                if item.get("file") not in scoped_file_set
            ]
            + snapshot["hotspots"],
            key=hotspot_sort_key,
        )
        snapshot["dead_code_candidates"] = sorted(
            [
                item
                for item in baseline_report.get("dead_code_candidates", [])
                if item.get("file") not in scoped_file_set
            ]
            + snapshot["dead_code_candidates"],
            key=dead_code_sort_key,
        )
        snapshot["agent_routing_queue"] = sorted(
            [
                item
                for item in baseline_report.get("agent_routing_queue", [])
                if item.get("file") not in scoped_file_set
            ]
            + snapshot["agent_routing_queue"],
            key=agent_routing_sort_key,
        )
        baseline_history = baseline_report.get("history_summary", {})
        current_history = snapshot.get("history_summary", {})
        merged_history_files = dict(baseline_history.get("files", {}))
        merged_history_files.update(
            {
                file_name: item
                for file_name, item in current_history.get("files", {}).items()
                if file_name in scoped_file_set
            }
        )
        snapshot["history_summary"] = {
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
        preserved_scope = baseline_report.get("scope", snapshot["scope"])
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
    lookup = ScopeLookup.from_files(repo_root=request.config.repo_root, files=files)
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


def _load_baseline_report(baseline_path: Path) -> dict[str, Any] | None:
    if not baseline_path.exists():
        return None
    baseline_report = json.loads(baseline_path.read_text(encoding="utf-8"))
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
    previous_profile = _set_active_profile(get_profile(resolved_request.config.profile))
    try:
        scope_state = _prepare_audit_scope(resolved_request)
        tool_run = _run_audit_tools(scope_state, resolved_request)
        hotspots = aggregate_hotspots(
            tool_run.ruff_signals + tool_run.lizard_signals + tool_run.complexipy_signals
        )
        tool_summaries = build_tool_summaries(
            ruff_signals=tool_run.ruff_signals,
            lizard_signals=tool_run.lizard_signals,
            complexipy_signals=tool_run.complexipy_signals,
            dead_code_candidates=tool_run.dead_code_candidates,
        )
        history_targets, history_tracked_files = _history_collection_inputs(
            request=resolved_request,
            scope_state=scope_state,
        )
        history_summary = collect_git_history_summary(
            repo_root=resolved_request.config.repo_root,
            targets=history_targets,
            tracked_files=history_tracked_files,
            current_scope_files=scope_state.current_scope_files,
            lookback_days=resolved_request.lookback_days,
            min_shared_commits=resolved_request.config.history.min_shared_commits,
            coupling_ignore_commit_file_count=resolved_request.config.history.coupling_ignore_commit_file_count,
            raw_path=scope_state.raw_dir / "git-history.txt",
        )
        coverage_summary = load_coverage_summary(
            coverage_json=resolved_request.coverage_json,
            repo_root=resolved_request.config.repo_root,
            tracked_files=scope_state.current_scope_files,
        )
        ambiguity_index = build_agent_ambiguity_index(
            repo_root=resolved_request.config.repo_root,
            files=scope_state.files,
        )
        agent_routing_queue = build_agent_routing_queue(
            scope_files=scope_state.current_scope_files,
            hotspots=hotspots,
            dead_code_candidates=tool_run.dead_code_candidates,
            history_summary=history_summary,
            coverage_summary=coverage_summary,
            ambiguity_index=ambiguity_index,
        )
        baseline_report = _load_baseline_report(resolved_request.baseline_path)
        baseline_diff = build_baseline_diff(
            current_hotspots=hotspots,
            current_dead_code_candidates=tool_run.dead_code_candidates,
            baseline_report=baseline_report,
            scope_files=scope_state.current_scope_files,
            config=resolved_request.config,
        )
        repo_verdict = build_repo_verdict(
            hotspots=hotspots,
            baseline_diff=baseline_diff,
            agent_routing_queue=agent_routing_queue,
            history_summary=history_summary,
        )
        report = _build_audit_report(
            _AuditReportContext(
                request=resolved_request,
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
        _write_audit_outputs(out_dir=resolved_request.out_dir, report=report)
        _maybe_update_baseline(
            request=resolved_request,
            scope_state=scope_state,
            baseline_report=baseline_report,
            report=report,
        )
        exit_code = int(
            bool(resolved_request.fail_on_regression and baseline_diff["has_regressions"])
        )
        return exit_code, report
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
    resolved_config = AuditConfig(
        repo_root=config.repo_root,
        profile=profile_name,
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
        help="Profile name. Defaults to tool.cremona.profile or generic-python.",
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
