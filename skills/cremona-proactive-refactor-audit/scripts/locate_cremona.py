#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any

DEFAULT_REPO_URL = "https://github.com/NeapolitanIcecream/cremona.git"
COMMON_HOME_PATHS = (
    "cremona",
    "code/cremona",
    "git/cremona",
    "gits/cremona",
    "projects/cremona",
    "repos/cremona",
    "src/cremona",
    "work/cremona",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Locate a Cremona executable or checkout and suggest scan commands."
    )
    parser.add_argument(
        "--target-repo",
        type=Path,
        help="Repository that will be audited. Used to tailor discovery and suggestions.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of shell-friendly key=value lines.",
    )
    return parser.parse_args()


def is_cremona_repo(path: Path) -> bool:
    pyproject_path = path / "pyproject.toml"
    cli_path = path / "src" / "cremona" / "cli.py"
    if not pyproject_path.is_file() or not cli_path.is_file():
        return False
    try:
        content = pyproject_path.read_text(encoding="utf-8")
    except OSError:
        return False
    return bool(
        re.search(r"(?m)^\s*name\s*=\s*[\"']cremona[\"']\s*$", content)
    )


def candidate_paths(target_repo: Path | None) -> list[Path]:
    candidates: list[Path] = []
    env_path = os.environ.get("CREMONA_REPO_PATH")
    if env_path:
        candidates.append(Path(env_path).expanduser())

    search_roots: list[Path] = [Path.cwd()]
    if target_repo is not None:
        resolved_target = target_repo.expanduser().resolve()
        if resolved_target.is_file():
            search_roots.append(resolved_target.parent)
        else:
            search_roots.append(resolved_target)

    for root in list(search_roots):
        search_roots.extend(root.parents)

    for root in search_roots:
        candidates.append(root)
        candidates.append(root / "cremona")

    home = Path.home()
    for relative_path in COMMON_HOME_PATHS:
        candidates.append(home / relative_path)

    deduped: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        expanded = candidate.expanduser()
        try:
            resolved = expanded.resolve(strict=False)
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        deduped.append(resolved)
    return deduped


def build_scan_command(*, target_repo: Path | None, executable: str | None, repo_root: Path | None) -> str:
    parts: list[str]
    if executable is not None:
        parts = [executable, "scan"]
    elif repo_root is not None:
        parts = ["uv", "run", "--project", str(repo_root), "cremona", "scan"]
    else:
        raise ValueError("Need an executable or repo_root to build a scan command.")
    if target_repo is not None:
        parts.append(str(target_repo))
    return " ".join(parts)


def suggested_clone_dir(target_repo: Path | None) -> Path:
    if target_repo is not None:
        resolved_target = target_repo.expanduser().resolve()
        anchor = resolved_target.parent if resolved_target.is_file() else resolved_target.parent
        return anchor / "cremona"
    home = Path.home()
    for root_name in ("gits", "src", "code", "projects", "work", "repos"):
        root = home / root_name
        if root.exists():
            return root / "cremona"
    return home / "gits" / "cremona"


def locate_cremona(target_repo: Path | None) -> dict[str, Any]:
    executable = shutil.which("cremona")
    if executable:
        return {
            "status": "found",
            "mode": "command",
            "executable": executable,
            "repo_root": None,
            "repo_url": DEFAULT_REPO_URL,
            "scan_command": build_scan_command(
                target_repo=target_repo,
                executable="cremona",
                repo_root=None,
            ),
        }

    for candidate in candidate_paths(target_repo):
        if is_cremona_repo(candidate):
            return {
                "status": "found",
                "mode": "repo",
                "executable": None,
                "repo_root": str(candidate),
                "repo_url": DEFAULT_REPO_URL,
                "scan_command": build_scan_command(
                    target_repo=target_repo,
                    executable=None,
                    repo_root=candidate,
                ),
            }

    clone_dir = suggested_clone_dir(target_repo)
    return {
        "status": "missing",
        "mode": "missing",
        "executable": None,
        "repo_root": None,
        "repo_url": DEFAULT_REPO_URL,
        "clone_command": f"git clone {DEFAULT_REPO_URL} {clone_dir}",
        "scan_command": build_scan_command(
            target_repo=target_repo,
            executable=None,
            repo_root=clone_dir,
        ),
    }


def render_plain(result: dict[str, Any]) -> str:
    lines: list[str] = []
    for key in (
        "status",
        "mode",
        "executable",
        "repo_root",
        "repo_url",
        "clone_command",
        "scan_command",
    ):
        value = result.get(key)
        if value is None:
            continue
        lines.append(f"{key}={value}")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    result = locate_cremona(args.target_repo)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(render_plain(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
