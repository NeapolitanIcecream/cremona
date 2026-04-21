from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from .models import AuditConfig, CoverageConfig, HistoryConfig, LizardBands, MetricBands, VultureBands
from ..profiles import DEFAULT_PROFILE, build_profile_registry, get_profile

REPO_ROOT = Path.cwd()

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
    profile_registry = build_profile_registry(config_data)
    profile_name = str(config_data.get("profile") or DEFAULT_PROFILE.name)
    get_profile(profile_name, profile_registry)
    return AuditConfig(
        repo_root=repo_root,
        profile=profile_name,
        profile_registry=profile_registry,
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

