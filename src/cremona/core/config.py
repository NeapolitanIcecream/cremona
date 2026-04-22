from __future__ import annotations

from collections.abc import Mapping
import tomllib
from pathlib import Path
from typing import Any

from ..profiles import DEFAULT_PROFILE, build_profile_registry, get_profile
from .models import (
    AuditConfig,
    CoverageConfig,
    HistoryConfig,
    LizardBands,
    MetricBands,
    VultureBands,
)

REPO_ROOT = Path.cwd()


def load_audit_config(*, repo_root: Path = REPO_ROOT) -> AuditConfig:
    config_data = _merge_cremona_config(
        defaults=_default_config_data(),
        overrides=_load_repo_config(repo_root / "pyproject.toml"),
    )
    profile_registry = build_profile_registry(config_data)
    profile_name = _validate_profile_name(config_data, profile_registry)
    return _build_audit_config(
        repo_root=repo_root,
        config_data=config_data,
        profile_name=profile_name,
        profile_registry=profile_registry,
    )


def _default_config_data() -> dict[str, Any]:
    return {
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
            "nloc_warning_min": 100,
            "nloc_warning_max": 149,
            "nloc_high_min": 150,
            "nloc_high_max": 199,
            "nloc_critical_min": 200,
            "parameter_warning_min": 7,
            "parameter_warning_max": 8,
            "parameter_high_min": 9,
            "parameter_high_max": 9,
            "parameter_critical_min": 10,
        },
        "complexipy": {
            "warning_min": 16,
            "warning_max": 29,
            "high_min": 30,
            "high_max": 49,
            "critical_min": 50,
        },
        "vulture": {
            "review_candidate_min": 70,
            "high_confidence_candidate_min": 80,
        },
        "history": {
            "lookback_days": 180,
            "min_shared_commits": 2,
            "coupling_ignore_commit_file_count": 25,
        },
        "coverage": {
            "coverage_json": "",
        },
    }


def _load_repo_config(pyproject_path: Path) -> dict[str, Any]:
    if not pyproject_path.exists():
        return {}
    data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    loaded = data.get("tool", {}).get("cremona", {})
    return loaded if isinstance(loaded, dict) else {}


def _merge_cremona_config(
    *,
    defaults: Mapping[str, Any],
    overrides: Mapping[str, Any],
) -> dict[str, Any]:
    config_data: dict[str, Any] = {
        key: _clone_config_value(value) for key, value in defaults.items()
    }
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(config_data.get(key), dict):
            merged = dict(config_data[key])
            merged.update(value)
            config_data[key] = merged
            continue
        config_data[key] = value
    return config_data


def _clone_config_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _clone_config_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_clone_config_value(item) for item in value]
    return value


def _validate_profile_name(
    config_data: Mapping[str, Any],
    profile_registry: Mapping[str, Any],
) -> str:
    profile_name = str(config_data.get("profile") or DEFAULT_PROFILE.name)
    get_profile(profile_name, profile_registry)
    return profile_name


def _build_audit_config(
    *,
    repo_root: Path,
    config_data: Mapping[str, Any],
    profile_name: str,
    profile_registry: Mapping[str, Any],
) -> AuditConfig:
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
            coverage_json=_resolve_coverage_json(
                repo_root=repo_root,
                coverage_data=config_data["coverage"],
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


def _resolve_coverage_json(
    *,
    repo_root: Path,
    coverage_data: Mapping[str, Any],
) -> Path | None:
    coverage_json = str(coverage_data.get("coverage_json") or "").strip()
    if not coverage_json:
        return None
    return resolve_repo_path(repo_root, coverage_json)


def resolve_repo_path(repo_root: Path, value: str) -> Path:
    candidate = Path(value)
    if candidate.is_absolute():
        return candidate
    return (repo_root / candidate).resolve()
