from __future__ import annotations

import ast
import csv
import fnmatch
import json
import os
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from ..core.models import AuditConfig, HotspotSignal, SEVERITY_RANK
from ..profiles import DEFAULT_DEAD_CODE_IGNORED_DECORATORS


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
    def from_files(
        cls,
        *,
        repo_root: Path,
        files: list[Path],
        ignored_decorators: frozenset[str] | None = None,
    ) -> ScopeLookup:
        rel_paths = [relative_path(path, repo_root) for path in files]
        grouped: dict[str, list[str]] = defaultdict(list)
        qualified_names_by_path: dict[str, frozenset[str]] = {}
        qualified_names_by_path_and_leaf: dict[str, dict[str, tuple[str, ...]]] = {}
        qualified_names_by_path_and_line: dict[str, dict[int, str]] = {}
        vulture_ignored_lines_by_path: dict[str, frozenset[int]] = {}
        active_ignored = (
            DEFAULT_DEAD_CODE_IGNORED_DECORATORS
            if ignored_decorators is None
            else ignored_decorators
        )
        for rel_path in rel_paths:
            grouped[Path(rel_path).name].append(rel_path)
            path = repo_root / rel_path
            symbol_index = build_symbol_index(
                path,
                ignored_decorators=active_ignored,
            )
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


def _candidate_reported_paths(reported: str, lookup: ScopeLookup) -> tuple[str, ...]:
    reported_path = Path(str(reported))
    if reported_path.is_absolute():
        rel_path = relative_path(reported_path, lookup.repo_root)
        return (rel_path,) if rel_path in lookup.allowed_rel_paths else ()
    rel_candidate = reported_path.as_posix()
    if rel_candidate in lookup.allowed_rel_paths:
        return (rel_candidate,)
    parts = reported_path.parts
    if parts:
        suffix_matches = tuple(
            sorted(
                rel_path
                for rel_path in lookup.allowed_rel_paths
                if Path(rel_path).parts[-len(parts) :] == parts
            )
        )
        if suffix_matches:
            return suffix_matches
    repo_candidate = relative_path(lookup.repo_root / reported_path, lookup.repo_root)
    if repo_candidate in lookup.allowed_rel_paths:
        return (repo_candidate,)
    return ()


def resolve_reported_path(reported: str, lookup: ScopeLookup) -> str | None:
    candidates = _candidate_reported_paths(reported, lookup)
    if len(candidates) == 1:
        return candidates[0]
    return None


def _resolve_complexipy_reported_path(
    *, reported: str, symbol: str, lookup: ScopeLookup
) -> str | None:
    rel_path = resolve_reported_path(reported, lookup)
    if rel_path is not None:
        return rel_path
    candidates = _candidate_reported_paths(reported, lookup)
    if len(candidates) <= 1:
        return None
    cleaned = str(symbol).strip()
    if not cleaned:
        return None
    exact_matches = [
        path
        for path in candidates
        if cleaned in lookup.qualified_names_by_path.get(path, frozenset())
    ]
    if len(exact_matches) == 1:
        return exact_matches[0]
    if exact_matches:
        return None
    leaf = cleaned.split("::")[-1].split(".")[-1]
    leaf_matches = [
        path
        for path in candidates
        if leaf in lookup.qualified_names_by_path_and_leaf.get(path, {})
    ]
    if len(leaf_matches) == 1:
        return leaf_matches[0]
    return None


@dataclass
class _SymbolIndexBuffers:
    qualified_names: list[str]
    by_leaf: dict[str, list[str]]
    by_line: dict[int, str]
    vulture_ignored_lines: set[int]


def build_symbol_index(
    path: Path,
    *,
    ignored_decorators: frozenset[str] | None = None,
) -> dict[str, Any]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    buffers = _SymbolIndexBuffers(
        qualified_names=[],
        by_leaf=defaultdict(list),
        by_line={},
        vulture_ignored_lines=set(),
    )
    active_ignored = (
        DEFAULT_DEAD_CODE_IGNORED_DECORATORS
        if ignored_decorators is None
        else ignored_decorators
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
                    ignored_decorators=active_ignored,
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
    ignored_decorators: frozenset[str],
) -> None:
    buffers.qualified_names.append(qualified)
    buffers.by_line[int(node.lineno)] = qualified
    buffers.by_leaf[node.name].append(qualified)
    if _has_vulture_ignored_decorator(node, ignored_decorators=ignored_decorators):
        buffers.vulture_ignored_lines.update(_vulture_ignored_line_span(node))


def _has_vulture_ignored_decorator(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    ignored_decorators: frozenset[str],
) -> bool:
    return any(
        _decorator_base_name(decorator) in ignored_decorators
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
        symbol = str(item.get("function_name") or "<unknown>")
        rel_path = resolve_reported_path(
            str(item.get("path") or item.get("file_name")),
            lookup,
        )
        if rel_path is None:
            rel_path = _resolve_complexipy_reported_path(
                reported=str(item.get("path") or item.get("file_name")),
                symbol=symbol,
                lookup=lookup,
            )
        if rel_path is None:
            continue
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
                "subsystem": "other",
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
