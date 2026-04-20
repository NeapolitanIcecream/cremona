from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


AmbiguityIndexBuilder = Callable[[Path, list[Path]], dict[str, dict[str, int]]]
SubsystemClassifier = Callable[[str], str]


@dataclass(frozen=True)
class Profile:
    name: str
    queue_order: tuple[str, ...]
    classify_subsystem: SubsystemClassifier
    build_ambiguity_index: AmbiguityIndexBuilder


def empty_ambiguity_signals() -> dict[str, int]:
    return {
        "module_package_shadow": 0,
        "wildcard_reexport": 0,
        "facade_reexport": 0,
        "legacy_keyword_hits": 0,
        "compat_request_wrapper": 0,
    }


def _relative_path(path: Path, repo_root: Path) -> str:
    return path.resolve().relative_to(repo_root.resolve()).as_posix()


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


def _build_python_ambiguity_index(
    *,
    repo_root: Path,
    files: list[Path],
    include_recoleta_compat: bool,
) -> dict[str, dict[str, int]]:
    index: dict[str, dict[str, int]] = {}
    for path in files:
        rel_path = _relative_path(path, repo_root)
        text = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError:
            tree = None
        signals = empty_ambiguity_signals()
        signals["module_package_shadow"] = int(path.with_suffix("").is_dir())
        if tree is not None:
            signals["wildcard_reexport"] = int(
                any(
                    isinstance(node, ast.ImportFrom)
                    and any(alias.name == "*" for alias in node.names)
                    for node in ast.walk(tree)
                )
            )
        if include_recoleta_compat and tree is not None:
            signals["facade_reexport"] = int(
                any(_is_facade_import(node) for node in ast.walk(tree))
                and any(_assigns_all_symbol(node) for node in ast.walk(tree))
            )
            signals["legacy_keyword_hits"] = len(
                re.findall(r"\blegacy_kwargs\b|\blegacy_[A-Za-z0-9_]*\b", text)
            )
            signals["compat_request_wrapper"] = int(
                "**legacy_kwargs" in text
                and re.search(
                    r"request\s*:\s*[^=\n]+?\|\s*None\s*=\s*None",
                    text,
                )
                is not None
            )
        index[rel_path] = signals
    return index


def _classify_generic_python_subsystem(rel_path: str) -> str:
    parts = Path(rel_path).parts
    if not parts:
        return "other"
    head = parts[0]
    if head in {"tests", "scripts", "docs"}:
        return head
    if len(parts) >= 2 and parts[1] == "__init__.py":
        return head
    return head or "other"


def _classify_recoleta_subsystem(rel_path: str) -> str:
    if rel_path.startswith("recoleta/pipeline"):
        return "pipeline"
    if rel_path.startswith("recoleta/cli"):
        return "cli"
    if rel_path.startswith("recoleta/storage"):
        return "storage"
    if rel_path.startswith("recoleta/rag"):
        return "rag"
    if rel_path.startswith("recoleta/translation"):
        return "translation"
    if rel_path.startswith("recoleta/sources") or rel_path.startswith("recoleta/extract"):
        return "sources"
    if (
        rel_path.startswith("recoleta/site")
        or rel_path.startswith("recoleta/publish")
        or rel_path.startswith("recoleta/presentation")
        or rel_path.startswith("recoleta/trend_materialize")
    ):
        return "site/render"
    return "other"


GENERIC_PYTHON_PROFILE = Profile(
    name="generic-python",
    queue_order=("src", "tests", "scripts", "docs", "other"),
    classify_subsystem=_classify_generic_python_subsystem,
    build_ambiguity_index=lambda repo_root, files: _build_python_ambiguity_index(
        repo_root=repo_root,
        files=files,
        include_recoleta_compat=False,
    ),
)

RECOLETA_PROFILE = Profile(
    name="recoleta",
    queue_order=(
        "pipeline",
        "site/render",
        "translation",
        "sources",
        "storage",
        "cli",
        "rag",
        "other",
    ),
    classify_subsystem=_classify_recoleta_subsystem,
    build_ambiguity_index=lambda repo_root, files: _build_python_ambiguity_index(
        repo_root=repo_root,
        files=files,
        include_recoleta_compat=True,
    ),
)

_PROFILES = {
    GENERIC_PYTHON_PROFILE.name: GENERIC_PYTHON_PROFILE,
    RECOLETA_PROFILE.name: RECOLETA_PROFILE,
}

DEFAULT_PROFILE = GENERIC_PYTHON_PROFILE


def get_profile(name: str) -> Profile:
    try:
        return _PROFILES[name]
    except KeyError as exc:
        available = ", ".join(sorted(_PROFILES))
        raise ValueError(f"Unknown profile {name!r}. Available profiles: {available}") from exc


def available_profiles() -> tuple[str, ...]:
    return tuple(sorted(_PROFILES))
