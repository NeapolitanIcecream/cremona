from __future__ import annotations

import json
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any, Literal, cast

import pytest

import cremona.scan as audit
from cremona.core import engine as core_engine
from tests._report_builders import (
    make_baseline_diff,
    make_dead_code_candidate,
    make_history_summary,
    make_hotspot,
    make_report,
    make_repo_verdict,
    make_routing_item,
    make_scope,
    make_signal,
    make_summary,
    make_tool_summaries,
)

CONFIG = audit.load_audit_config(repo_root=Path(__file__).resolve().parents[1])
audit._set_active_profile(audit.get_profile("generic-python"))


@contextmanager
def _use_profile(profile: audit.Profile):
    previous = audit._set_active_profile(profile)
    try:
        yield
    finally:
        audit._set_active_profile(previous)


def _lookup_for(tmp_path: Path, *relative_paths: str) -> audit.ScopeLookup:
    files: list[Path] = []
    for relative_path in relative_paths:
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("pass\n", encoding="utf-8")
        files.append(path)
    return audit.ScopeLookup.from_files(repo_root=tmp_path, files=files)


def _signal(
    *,
    tool: Literal["ruff", "lizard", "complexipy"],
    file: str = "pkg/example.py",
    symbol: str = "example",
    severity: Literal["warning", "high", "critical"] = "warning",
    metrics: dict[str, int] | None = None,
) -> audit.HotspotSignal:
    return audit.HotspotSignal(
        tool=tool,
        file=file,
        symbol=symbol,
        line=10,
        severity=severity,
        metrics=metrics or {"complexity": 12},
        message="sample",
    )


def _coverage_payload() -> dict[str, object]:
    return {
        "meta": {"version": "7.0"},
        "files": {
            "pkg/branchy.py": {
                "summary": {
                    "covered_branches": 6,
                    "num_branches": 8,
                    "covered_lines": 10,
                    "num_statements": 12,
                }
            },
            "pkg/line_only.py": {
                "summary": {
                    "covered_lines": 9,
                    "num_statements": 12,
                }
            },
            "pkg/unknown.py": {"summary": {}},
        },
    }


def _partial_scope_baseline_report() -> dict[str, Any]:
    return {
        "schema_version": 3,
        "scope": make_scope(
            files=["pkg/in_scope.py", "pkg/out_of_scope.py"],
            file_count=2,
        ),
        "hotspots": [
            make_hotspot(
                id="pkg/in_scope.py::branchy",
                file="pkg/in_scope.py",
                classification="monitor",
                metrics={"ruff": {"complexity": 12}},
                signals=[
                    make_signal(
                        tool="ruff",
                        severity="warning",
                        symbol="branchy",
                        metrics={"complexity": 12},
                    )
                ],
            ),
            make_hotspot(
                id="pkg/out_of_scope.py::other_hotspot",
                file="pkg/out_of_scope.py",
                symbol="other_hotspot",
                classification="refactor_now",
                tools=["complexipy"],
                metrics={"complexipy": {"complexity": 55}},
                signals=[
                    make_signal(
                        tool="complexipy",
                        severity="critical",
                        symbol="other_hotspot",
                        line=20,
                        metrics={"complexity": 55},
                        message="complexity=55",
                    )
                ],
            ),
        ],
        "dead_code_candidates": [
            make_dead_code_candidate(
                id="pkg/out_of_scope.py::function::unused_helper",
                file="pkg/out_of_scope.py",
            )
        ],
        "agent_routing_queue": [
            make_routing_item(
                file="pkg/out_of_scope.py",
                priority_score=80,
                priority_band="investigate_now",
                change_frequency=8,
                churn=100,
                dead_code_candidate_count=1,
                hotspot_summary={
                    "refactor_now": 1,
                    "refactor_soon": 0,
                    "monitor": 0,
                    "multi_tool_monitor": 0,
                    "top_symbols": [],
                },
                priority_components={
                    "change_score": 10,
                    "coupling_score": 0,
                    "static_score": 5,
                    "subsystem_priority_score": 0,
                    "routing_signal_score": 0,
                    "routing_bonus_score": 0,
                    "dead_code_score": 3,
                    "coverage_risk_score": 0,
                },
            )
        ],
        "history_summary": make_history_summary(
            max_commit_frequency=8,
            max_churn=100,
            files={
                "pkg/out_of_scope.py": {
                    "commit_frequency": 8,
                    "churn": 100,
                    "top_coupled_files": [],
                }
            },
        ),
    }


def _partial_scope_current_report() -> dict[str, Any]:
    return make_report(
        summary=make_summary(
            files_scanned=1,
            hotspots_total=1,
            refactor_soon_total=1,
            agent_routing_queue_total=1,
            investigate_soon_total=1,
        ),
        repo_verdict=make_repo_verdict(
            status="strained",
            debt_status="strained",
            routing_pressure="investigate_soon",
            summary=(
                "Existing structural debt remains, but the current scope did not regress. "
                "Routing pressure is investigate_soon. Signal health is partial: missing coverage."
            ),
            signal_health="partial",
            missing_signals=["coverage"],
            investigate_soon_total=1,
        ),
        hotspots=[
            make_hotspot(
                id="pkg/in_scope.py::branchy",
                file="pkg/in_scope.py",
                classification="refactor_soon",
                metrics={"ruff": {"complexity": 26}},
                signals=[
                    make_signal(
                        tool="ruff",
                        severity="critical",
                        symbol="branchy",
                        metrics={"complexity": 26},
                        message="complexity=26",
                    )
                ],
            )
        ],
        tool_summaries=make_tool_summaries(
            ruff={"findings_total": 1, "warning": 0, "high": 0, "critical": 1},
        ),
        baseline_diff=make_baseline_diff(
            has_regressions=True,
            new=[{"kind": "hotspot"}],
        ),
        agent_routing_queue=[
            make_routing_item(
                file="pkg/in_scope.py",
                priority_score=50,
                priority_band="investigate_soon",
                change_frequency=5,
                churn=40,
                coverage={"mode": "line", "fraction": 0.5},
                hotspot_summary={
                    "refactor_now": 0,
                    "refactor_soon": 1,
                    "monitor": 0,
                    "multi_tool_monitor": 0,
                    "top_symbols": [],
                },
                priority_components={
                    "change_score": 10,
                    "coupling_score": 0,
                    "static_score": 3,
                    "subsystem_priority_score": 0,
                    "routing_signal_score": 0,
                    "routing_bonus_score": 0,
                    "dead_code_score": 0,
                    "coverage_risk_score": 5,
                },
            )
        ],
        history_summary=make_history_summary(
            max_commit_frequency=5,
            max_churn=40,
            files={
                "pkg/in_scope.py": {
                    "commit_frequency": 5,
                    "churn": 40,
                    "top_coupled_files": [],
                }
            },
        ),
        scope=make_scope(files=["pkg/in_scope.py"], file_count=1),
    )


def _partial_scope_snapshot_inputs() -> tuple[dict[str, Any], dict[str, Any]]:
    return (_partial_scope_baseline_report(), _partial_scope_current_report())


def test_parse_ruff_findings_reads_c901_json(tmp_path: Path) -> None:
    lookup = _lookup_for(tmp_path, "pkg/mod.py")
    raw_text = json.dumps(
        [
            {
                "code": "C901",
                "filename": str(tmp_path / "pkg" / "mod.py"),
                "location": {"row": 42, "column": 5},
                "message": "`branchy` is too complex (12 > 10)",
            }
        ]
    )

    findings = audit.parse_ruff_findings(
        raw_text=raw_text,
        lookup=lookup,
        config=CONFIG,
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.file == "pkg/mod.py"
    assert finding.symbol == "branchy"
    assert finding.severity == "warning"
    assert finding.metrics["complexity"] == 12


def test_parse_lizard_findings_reads_csv_thresholds(tmp_path: Path) -> None:
    lookup = _lookup_for(tmp_path, "pkg/mod.py")
    raw_text = (
        '200,31,1241,10,154,"branchy@42-196@pkg/mod.py","pkg/mod.py",'
        '"branchy","branchy( a, b, c, d, e, f, g )",42,196\n'
    )

    findings = audit.parse_lizard_findings(
        raw_text=raw_text,
        lookup=lookup,
        config=CONFIG,
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "critical"
    assert finding.metrics["ccn"] == 31
    assert finding.metrics["nloc"] == 200
    assert finding.metrics["parameter_count"] == 10


def test_parse_lizard_findings_applies_updated_nloc_bands(tmp_path: Path) -> None:
    lookup = _lookup_for(tmp_path, "pkg/mod.py")

    for nloc, expected in [
        (99, None),
        (100, "warning"),
        (149, "warning"),
        (150, "high"),
        (199, "high"),
        (200, "critical"),
    ]:
        raw_text = (
            f'{nloc},10,1241,3,154,"branchy@42-196@pkg/mod.py","pkg/mod.py",'
            '"branchy","branchy( a, b, c )",42,196\n'
        )

        findings = audit.parse_lizard_findings(
            raw_text=raw_text,
            lookup=lookup,
            config=CONFIG,
        )

        actual = findings[0].severity if findings else None
        assert actual == expected


def test_parse_lizard_findings_applies_updated_parameter_bands(tmp_path: Path) -> None:
    lookup = _lookup_for(tmp_path, "pkg/mod.py")

    for parameter_count, expected in [
        (6, None),
        (7, "warning"),
        (8, "warning"),
        (9, "high"),
        (10, "critical"),
    ]:
        raw_text = (
            f'50,10,1241,{parameter_count},154,"branchy@42-196@pkg/mod.py","pkg/mod.py",'
            '"branchy","branchy( a, b, c )",42,196\n'
        )

        findings = audit.parse_lizard_findings(
            raw_text=raw_text,
            lookup=lookup,
            config=CONFIG,
        )

        actual = findings[0].severity if findings else None
        assert actual == expected


def test_parse_complexipy_findings_reads_json_thresholds(tmp_path: Path) -> None:
    lookup = _lookup_for(tmp_path, "pkg/mod.py")
    raw_text = json.dumps(
        [
            {
                "complexity": 55,
                "file_name": "mod.py",
                "function_name": "Example::branchy",
                "path": "pkg/mod.py",
            }
        ]
    )

    findings = audit.parse_complexipy_findings(
        raw_text=raw_text,
        lookup=lookup,
        config=CONFIG,
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.file == "pkg/mod.py"
    assert finding.symbol == "Example::branchy"
    assert finding.severity == "critical"
    assert finding.metrics["complexity"] == 55


def test_collect_python_files_raises_for_missing_target(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="Scope target does not exist"):
        audit.collect_python_files(
            repo_root=tmp_path,
            targets=["missing.py"],
            exclude_patterns=(),
        )


def test_collect_python_files_collects_files_from_directories_and_file_targets(
    tmp_path: Path,
) -> None:
    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    alpha = package_dir / "alpha.py"
    beta = package_dir / "beta.py"
    notes = package_dir / "notes.txt"
    alpha.write_text("pass\n", encoding="utf-8")
    beta.write_text("pass\n", encoding="utf-8")
    notes.write_text("ignore\n", encoding="utf-8")

    files = audit.collect_python_files(
        repo_root=tmp_path,
        targets=["pkg", "pkg/alpha.py"],
        exclude_patterns=(),
    )

    assert files == [alpha.resolve(), beta.resolve()]


def test_collect_python_files_skips_excluded_targets_and_children(tmp_path: Path) -> None:
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    kept = src_dir / "kept.py"
    ignored = src_dir / "ignored.py"
    skipped_dir = tmp_path / "skip"
    skipped_dir.mkdir()
    skipped = skipped_dir / "skip_me.py"
    kept.write_text("pass\n", encoding="utf-8")
    ignored.write_text("pass\n", encoding="utf-8")
    skipped.write_text("pass\n", encoding="utf-8")

    files = audit.collect_python_files(
        repo_root=tmp_path,
        targets=["src", "skip"],
        exclude_patterns=("ignored.py", "skip"),
    )

    assert files == [kept.resolve()]


def test_parse_complexipy_findings_disambiguates_duplicate_basenames(
    tmp_path: Path,
) -> None:
    """Regression: basename-only complexipy paths must still resolve duplicate files."""
    core_path = tmp_path / "pkg" / "core" / "engine.py"
    core_path.parent.mkdir(parents=True, exist_ok=True)
    core_path.write_text(
        """
def build_history_summary() -> int:
    return 1
""".strip()
        + "\n",
        encoding="utf-8",
    )
    tools_path = tmp_path / "pkg" / "python_tools" / "engine.py"
    tools_path.parent.mkdir(parents=True, exist_ok=True)
    tools_path.write_text(
        """
def collect_python_files() -> list[str]:
    return []
""".strip()
        + "\n",
        encoding="utf-8",
    )
    lookup = audit.ScopeLookup.from_files(
        repo_root=tmp_path,
        files=[core_path, tools_path],
    )
    raw_text = json.dumps(
        [
            {
                "complexity": 27,
                "file_name": "engine.py",
                "function_name": "build_history_summary",
                "path": "engine.py",
            },
            {
                "complexity": 18,
                "file_name": "engine.py",
                "function_name": "collect_python_files",
                "path": "engine.py",
            },
        ]
    )

    findings = audit.parse_complexipy_findings(
        raw_text=raw_text,
        lookup=lookup,
        config=CONFIG,
    )

    assert [(item.file, item.symbol) for item in findings] == [
        ("pkg/core/engine.py", "build_history_summary"),
        ("pkg/python_tools/engine.py", "collect_python_files"),
    ]


def test_parse_complexipy_findings_prefers_exact_symbol_before_leaf_fallback(
    tmp_path: Path,
) -> None:
    """Regression: exact qualified matches must win before shared leaf-name matches."""
    alpha_path = tmp_path / "pkg" / "alpha" / "engine.py"
    alpha_path.parent.mkdir(parents=True, exist_ok=True)
    alpha_path.write_text(
        """
class A:
    def run(self) -> int:
        return 1
""".strip()
        + "\n",
        encoding="utf-8",
    )
    beta_path = tmp_path / "pkg" / "beta" / "engine.py"
    beta_path.parent.mkdir(parents=True, exist_ok=True)
    beta_path.write_text(
        """
class B:
    def run(self) -> int:
        return 2
""".strip()
        + "\n",
        encoding="utf-8",
    )
    lookup = audit.ScopeLookup.from_files(
        repo_root=tmp_path,
        files=[alpha_path, beta_path],
    )
    raw_text = json.dumps(
        [
            {
                "complexity": 18,
                "file_name": "engine.py",
                "function_name": "A::run",
                "path": "engine.py",
            }
        ]
    )

    findings = audit.parse_complexipy_findings(
        raw_text=raw_text,
        lookup=lookup,
        config=CONFIG,
    )

    assert [(item.file, item.symbol) for item in findings] == [
        ("pkg/alpha/engine.py", "A::run"),
    ]


def test_resolve_reported_path_falls_back_to_unique_basename_for_prefixed_paths(
    tmp_path: Path,
) -> None:
    lookup = _lookup_for(tmp_path, "src/bar.py")

    resolved = audit.resolve_reported_path("foo/bar.py", lookup)

    assert resolved == "src/bar.py"


def test_parse_vulture_candidates_reads_text_output(tmp_path: Path) -> None:
    lookup = _lookup_for(tmp_path, "pkg/mod.py")
    raw_text = (
        "pkg/mod.py:18: unused function 'unused_helper' (82% confidence, 12 lines)\n"
    )

    candidates = audit.parse_vulture_candidates(
        raw_text=raw_text,
        lookup=lookup,
        config=CONFIG,
    )

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate["classification"] == "high_confidence_candidate"
    assert candidate["confidence"] == 82
    assert candidate["symbol"] == "unused_helper"


def test_parse_vulture_candidates_applies_updated_confidence_bands(
    tmp_path: Path,
) -> None:
    lookup = _lookup_for(tmp_path, "pkg/mod.py")

    for confidence, expected in [
        (69, []),
        (70, ["review_candidate"]),
        (80, ["high_confidence_candidate"]),
    ]:
        raw_text = (
            "pkg/mod.py:18: unused function 'unused_helper' "
            f"({confidence}% confidence, 12 lines)\n"
        )

        candidates = audit.parse_vulture_candidates(
            raw_text=raw_text,
            lookup=lookup,
            config=CONFIG,
        )

        assert [item["classification"] for item in candidates] == expected


def test_parse_vulture_candidates_ignores_pydantic_validator_methods(
    tmp_path: Path,
) -> None:
    path = tmp_path / "pkg" / "model.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        """
from pydantic import BaseModel, field_validator


class Example(BaseModel):
    value: int

    @field_validator("value")
    @classmethod
    def _validate_value(cls, value: int) -> int:
        return value
""".strip()
        + "\n",
        encoding="utf-8",
    )
    lookup = audit.ScopeLookup.from_files(repo_root=tmp_path, files=[path])
    raw_text = "pkg/model.py:8: unused method '_validate_value' (60% confidence)\n"

    candidates = audit.parse_vulture_candidates(
        raw_text=raw_text,
        lookup=lookup,
        config=CONFIG,
    )

    assert candidates == []


def test_parse_vulture_candidates_ignores_cli_entrypoint_decorators(
    tmp_path: Path,
) -> None:
    path = tmp_path / "pkg" / "cli.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        """
class FakeTyper:
    def command(self, name: str):
        def decorator(fn):
            return fn
        return decorator

    def callback(self, *, invoke_without_command: bool = False):
        def decorator(fn):
            return fn
        return decorator

    def group(self, name: str):
        def decorator(fn):
            return fn
        return decorator


app = FakeTyper()


@app.command("freshness")
def inspect_freshness() -> None:
    return None


@app.callback(invoke_without_command=True)
def main_callback() -> None:
    return None


@app.group("admin")
def admin_group() -> None:
    return None
""".strip()
        + "\n",
        encoding="utf-8",
    )
    lookup = audit.ScopeLookup.from_files(repo_root=tmp_path, files=[path])
    raw_text = "\n".join(
        [
            "pkg/cli.py:22: unused function 'inspect_freshness' (60% confidence)",
            "pkg/cli.py:27: unused function 'main_callback' (60% confidence)",
            "pkg/cli.py:32: unused function 'admin_group' (60% confidence)",
        ]
    )

    candidates = audit.parse_vulture_candidates(
        raw_text=raw_text,
        lookup=lookup,
        config=CONFIG,
    )

    assert candidates == []


def test_load_audit_config_treats_undefined_legacy_profile_name_as_unknown_profile(
    tmp_path: Path,
) -> None:
    """Regression: undefined legacy profile names should use the generic unknown-profile path."""
    legacy_profile_name = "reco" "leta"
    (tmp_path / "pyproject.toml").write_text(
        f"""
[tool.cremona]
profile = "{legacy_profile_name}"
""".strip()
        + "\n",
        encoding="utf-8",
    )

    try:
        audit.load_audit_config(repo_root=tmp_path)
    except ValueError as exc:
        message = str(exc)
    else:
        raise AssertionError("Expected unknown profile to be rejected")

    assert f"Unknown profile {legacy_profile_name!r}" in message
    assert "Available profiles:" in message


def test_load_audit_config_accepts_custom_profile_named_like_legacy_repo(
    tmp_path: Path,
) -> None:
    """Regression: a repo-specific profile may reuse the legacy project name without special handling."""
    legacy_profile_name = "reco" "leta"
    (tmp_path / "pyproject.toml").write_text(
        f"""
[tool.cremona]
profile = "{legacy_profile_name}"

[tool.cremona.profiles.{legacy_profile_name}]
base = "generic-python"
""".strip()
        + "\n",
        encoding="utf-8",
    )

    config = audit.load_audit_config(repo_root=tmp_path)

    assert config.profile == legacy_profile_name
    assert legacy_profile_name in config.profile_registry
    assert audit.get_profile(legacy_profile_name, config.profile_registry).name == legacy_profile_name


def test_load_audit_config_compiles_declared_profile(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[tool.cremona]
profile = "workflow-app"
targets = ["app"]

[tool.cremona.profiles.workflow-app]
base = "generic-python"
queue_order = ["pipeline", "cli", "other"]
fallback_subsystem = "other"

[[tool.cremona.profiles.workflow-app.subsystems]]
name = "pipeline"
include = ["app/pipeline/**"]

[[tool.cremona.profiles.workflow-app.subsystems]]
name = "cli"
include = ["app/cli/**"]

[[tool.cremona.profiles.workflow-app.signals]]
name = "kwargs_bridge_hits"
kind = "regex_count"
pattern = '\\blegacy_[A-Za-z0-9_]*\\b'
points_per = 10
max_points = 6

[[tool.cremona.profiles.workflow-app.routing_bonuses]]
name = "migration_pressure"
points = 4
all = [
  { source = "signal", name = "kwargs_bridge_hits", op = ">=", value = 25 },
  { source = "component", name = "coupling_score", op = ">=", value = 10 },
]
""".strip()
        + "\n",
        encoding="utf-8",
    )

    config = audit.load_audit_config(repo_root=tmp_path)
    profile = config.profile_registry["workflow-app"]

    assert config.profile == "workflow-app"
    assert tuple(config.profile_registry) == ("generic-python", "workflow-app")
    assert profile.queue_order == ("pipeline", "cli", "other")
    assert profile.classify_subsystem("app/pipeline/stage.py") == "pipeline"
    assert profile.classify_subsystem("app/cli/app.py") == "cli"
    assert profile.classify_subsystem("app/misc.py") == "other"
    assert "kwargs_bridge_hits" in profile.routing_signal_names


def test_load_audit_config_uses_bootstrap_history_defaults(tmp_path: Path) -> None:
    config = audit.load_audit_config(repo_root=tmp_path)

    assert config.history.lookback_days == 180
    assert config.history.min_shared_commits == 2
    assert config.history.coupling_ignore_commit_file_count == 25
    assert CONFIG.history.min_shared_commits == config.history.min_shared_commits


def test_load_audit_config_merges_partial_nested_overrides(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[tool.cremona]

[tool.cremona.ruff]
warning_min = 12
""".strip()
        + "\n",
        encoding="utf-8",
    )

    config = audit.load_audit_config(repo_root=tmp_path)

    assert config.ruff.warning_min == 12
    assert config.ruff.warning_max == 15
    assert config.ruff.high_min == 16
    assert config.ruff.critical_min == 25


def test_load_audit_config_resolves_absolute_paths(tmp_path: Path) -> None:
    out_dir = tmp_path / "reports"
    baseline = tmp_path / "quality" / "baseline.json"
    (tmp_path / "pyproject.toml").write_text(
        f"""
[tool.cremona]
out_dir = "{out_dir}"
baseline = "{baseline}"
""".strip()
        + "\n",
        encoding="utf-8",
    )

    config = audit.load_audit_config(repo_root=tmp_path)

    assert config.out_dir == out_dir
    assert config.baseline == baseline


def test_load_audit_config_normalizes_blank_coverage_json_to_none(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[tool.cremona.coverage]
coverage_json = "   "
""".strip()
        + "\n",
        encoding="utf-8",
    )

    config = audit.load_audit_config(repo_root=tmp_path)

    assert config.coverage.coverage_json is None


def test_repository_uses_self_host_profile() -> None:
    assert CONFIG.profile == "cremona-self-host"
    assert "cremona-self-host" in CONFIG.profile_registry


def test_load_audit_config_rejects_invalid_profile_rules(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[tool.cremona]
profile = "broken"

[tool.cremona.profiles.broken]
base = "generic-python"
queue_order = ["missing", "other"]
fallback_subsystem = "other"

[[tool.cremona.profiles.broken.routing_bonuses]]
name = "bad_bonus"
points = 4
all = [{ source = "component", name = "mystery_score", op = ">=", value = 1 }]
""".strip()
        + "\n",
        encoding="utf-8",
    )

    try:
        audit.load_audit_config(repo_root=tmp_path)
    except ValueError as exc:
        message = str(exc)
    else:
        raise AssertionError("Expected invalid custom profile to be rejected")

    assert "queue_order" in message or "mystery_score" in message


def test_profile_dead_code_ignored_decorators_can_override_defaults(
    tmp_path: Path,
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[tool.cremona]
profile = "workflow-app"

[tool.cremona.profiles.workflow-app]
base = "generic-python"
fallback_subsystem = "other"

[tool.cremona.profiles.workflow-app.dead_code]
ignored_decorators = ["workflow_step"]
inherit_default_ignored_decorators = false
""".strip()
        + "\n",
        encoding="utf-8",
    )
    config = audit.load_audit_config(repo_root=tmp_path)
    profile = audit.get_profile("workflow-app", config.profile_registry)

    path = tmp_path / "pkg" / "workflow.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        """
def workflow_step(fn):
    return fn


@workflow_step
def staged_task() -> None:
    return None
""".strip()
        + "\n",
        encoding="utf-8",
    )
    lookup = audit.ScopeLookup.from_files(
        repo_root=tmp_path,
        files=[path],
        ignored_decorators=profile.dead_code_ignored_decorators,
    )

    candidates = audit.parse_vulture_candidates(
        raw_text="pkg/workflow.py:5: unused function 'staged_task' (60% confidence)\n",
        lookup=lookup,
        config=config,
    )

    assert candidates == []
    assert profile.dead_code_ignored_decorators == frozenset({"workflow_step"})


def test_profile_dead_code_ignored_decorators_can_be_explicitly_empty(
    tmp_path: Path,
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[tool.cremona]
profile = "workflow-app"

[tool.cremona.profiles.workflow-app]
base = "generic-python"
fallback_subsystem = "other"

[tool.cremona.profiles.workflow-app.dead_code]
ignored_decorators = []
inherit_default_ignored_decorators = false
""".strip()
        + "\n",
        encoding="utf-8",
    )
    config = audit.load_audit_config(repo_root=tmp_path)
    profile = audit.get_profile("workflow-app", config.profile_registry)

    path = tmp_path / "pkg" / "cli.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        """
def command(fn):
    return fn


@command
def entrypoint() -> None:
    return None
""".strip()
        + "\n",
        encoding="utf-8",
    )
    lookup = audit.ScopeLookup.from_files(
        repo_root=tmp_path,
        files=[path],
        ignored_decorators=profile.dead_code_ignored_decorators,
    )

    candidates = audit.parse_vulture_candidates(
        raw_text="pkg/cli.py:5: unused function 'entrypoint' (70% confidence)\n",
        lookup=lookup,
        config=config,
    )

    assert [candidate["symbol"] for candidate in candidates] == ["entrypoint"]
    assert profile.dead_code_ignored_decorators == frozenset()


def test_custom_profile_without_subsystem_rules_keeps_generic_classifier(
    tmp_path: Path,
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[tool.cremona]
profile = "workflow-app"

[tool.cremona.profiles.workflow-app]
base = "generic-python"

[[tool.cremona.profiles.workflow-app.signals]]
name = "kwargs_bridge_hits"
kind = "regex_count"
pattern = "\\blegacy_[A-Za-z0-9_]*\\b"
points_per = 10
max_points = 6
""".strip()
        + "\n",
        encoding="utf-8",
    )

    config = audit.load_audit_config(repo_root=tmp_path)
    profile = audit.get_profile("workflow-app", config.profile_registry)

    assert profile.classifier_kind == audit.DEFAULT_PROFILE.classifier_kind
    assert profile.queue_order == audit.DEFAULT_PROFILE.queue_order
    assert profile.classify_subsystem("src/pkg/example.py") == "src"
    assert profile.classify_subsystem("tests/test_example.py") == "tests"
    assert profile.classify_subsystem("docs/guide.md") == "docs"


def test_parse_lizard_findings_keeps_same_leaf_methods_separate(tmp_path: Path) -> None:
    path = tmp_path / "pkg" / "mod.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        """
class Foo:
    def __init__(self) -> None:
        self.value = 1


class Bar:
    def __init__(self) -> None:
        self.value = 2
""".strip()
        + "\n",
        encoding="utf-8",
    )
    lookup = audit.ScopeLookup.from_files(repo_root=tmp_path, files=[path])
    raw_text = (
        '80,15,16,6,80,"__init__@2-3@pkg/mod.py","pkg/mod.py","__init__",'
        '"__init__( self )",2,3\n'
        '80,15,16,6,80,"__init__@7-8@pkg/mod.py","pkg/mod.py","__init__",'
        '"__init__( self )",7,8\n'
    )

    findings = audit.parse_lizard_findings(
        raw_text=raw_text,
        lookup=lookup,
        config=CONFIG,
    )

    assert [finding.symbol for finding in findings] == [
        "Foo::__init__",
        "Bar::__init__",
    ]
    hotspots = audit.aggregate_hotspots(findings, config=CONFIG)
    assert len(hotspots) == 2


def test_aggregate_hotspots_marks_single_warning_as_monitor() -> None:
    hotspots = audit.aggregate_hotspots(
        [
            _signal(
                tool="ruff",
                severity="warning",
                metrics={"complexity": 12},
            )
        ],
        config=CONFIG,
    )

    assert len(hotspots) == 1
    assert hotspots[0]["classification"] == "monitor"


def test_aggregate_hotspots_keeps_two_warning_tools_at_monitor() -> None:
    hotspots = audit.aggregate_hotspots(
        [
            _signal(
                tool="ruff",
                severity="warning",
                metrics={"complexity": 12},
            ),
            _signal(
                tool="lizard",
                severity="warning",
                metrics={"ccn": 16, "nloc": 90, "parameter_count": 4},
            ),
        ],
        config=CONFIG,
    )

    assert hotspots[0]["classification"] == "monitor"


def test_aggregate_hotspots_marks_three_warning_tools_as_refactor_soon() -> None:
    hotspots = audit.aggregate_hotspots(
        [
            _signal(
                tool="ruff",
                severity="warning",
                metrics={"complexity": 12},
            ),
            _signal(
                tool="lizard",
                severity="warning",
                metrics={"ccn": 16, "nloc": 90, "parameter_count": 4},
            ),
            _signal(
                tool="complexipy",
                severity="warning",
                metrics={"complexity": 18},
            ),
        ],
        config=CONFIG,
    )

    assert hotspots[0]["classification"] == "refactor_soon"


def test_aggregate_hotspots_marks_critical_complexity_as_refactor_now() -> None:
    hotspots = audit.aggregate_hotspots(
        [
            _signal(
                tool="complexipy",
                severity="critical",
                metrics={"complexity": 55},
            )
        ],
        config=CONFIG,
    )

    assert hotspots[0]["classification"] == "refactor_now"


def test_aggregate_hotspots_keeps_nloc_only_critical_at_refactor_soon() -> None:
    """Regression: long functions should not become refactor_now without critical CCN."""
    hotspots = audit.aggregate_hotspots(
        [
            _signal(
                tool="lizard",
                severity="critical",
                metrics={"ccn": 3, "nloc": 180, "parameter_count": 0},
            )
        ],
        config=CONFIG,
    )

    assert hotspots[0]["classification"] == "refactor_soon"


def test_aggregate_hotspots_marks_critical_ruff_as_refactor_soon() -> None:
    hotspots = audit.aggregate_hotspots(
        [
            _signal(
                tool="ruff",
                severity="critical",
                metrics={"complexity": 26},
            )
        ],
        config=CONFIG,
    )

    assert hotspots[0]["classification"] == "refactor_soon"


def test_aggregate_hotspots_requires_explicit_config() -> None:
    try:
        cast(Any, audit.aggregate_hotspots)([])
    except TypeError as exc:
        message = str(exc)
    else:
        raise AssertionError("Expected aggregate_hotspots() without config to fail")

    assert "config" in message


def test_build_history_summary_reads_commit_frequency_churn_and_coupling() -> None:
    raw_text = "\n".join(
        [
            "commit a1",
            "4\t1\tpkg/cli/app.py",
            "1\t0\tpkg/pipeline/service.py",
            "commit b2",
            "2\t2\tpkg/cli/app.py",
            "3\t1\tpkg/pipeline/service.py",
            "1\t0\tpkg/translation.py",
            "commit c3",
            "5\t0\tpkg/translation.py",
            "",
        ]
    )

    summary = audit.build_history_summary(
        raw_text=raw_text,
        tracked_files={
            "pkg/cli/app.py",
            "pkg/pipeline/service.py",
            "pkg/translation.py",
        },
        current_scope_files=[
            "pkg/cli/app.py",
            "pkg/pipeline/service.py",
        ],
        min_shared_commits=2,
        coupling_ignore_commit_file_count=10,
        lookback_days=180,
    )

    assert summary["status"] == "available"
    assert summary["max_commit_frequency"] == 2
    assert summary["max_churn"] == 9
    cli_history = summary["files"]["pkg/cli/app.py"]
    assert cli_history["commit_frequency"] == 2
    assert cli_history["churn"] == 9
    assert cli_history["top_coupled_files"] == [
        {
            "file": "pkg/pipeline/service.py",
            "shared_commits": 2,
            "in_scope": True,
        }
    ]


def test_build_history_summary_marks_git_unavailable(monkeypatch) -> None:
    def _fail(**_: object) -> None:
        raise RuntimeError("Command not found: git")

    monkeypatch.setattr(core_engine, "run_command", _fail)

    summary = audit.collect_git_history_summary(
        repo_root=Path.cwd(),
        targets=["pkg"],
        tracked_files={"pkg/example.py"},
        current_scope_files=["pkg/example.py"],
        lookback_days=180,
        min_shared_commits=3,
        coupling_ignore_commit_file_count=25,
    )

    assert summary["status"] == "unavailable"
    assert summary["files"]["pkg/example.py"]["commit_frequency"] == 0
    assert summary["files"]["pkg/example.py"]["top_coupled_files"] == []


def test_build_history_summary_ignores_sweep_commit_for_coupling() -> None:
    raw_text = "\n".join(
        [
            "commit a1",
            "1\t0\tpkg/a.py",
            "1\t0\tpkg/b.py",
            "1\t0\tpkg/c.py",
            "commit b2",
            "1\t0\tpkg/a.py",
            "1\t0\tpkg/b.py",
            "",
        ]
    )

    summary = audit.build_history_summary(
        raw_text=raw_text,
        tracked_files={
            "pkg/a.py",
            "pkg/b.py",
            "pkg/c.py",
        },
        current_scope_files=[
            "pkg/a.py",
            "pkg/b.py",
            "pkg/c.py",
        ],
        min_shared_commits=1,
        coupling_ignore_commit_file_count=2,
        lookback_days=180,
    )

    assert summary["files"]["pkg/a.py"]["commit_frequency"] == 2
    assert summary["files"]["pkg/a.py"]["top_coupled_files"] == [
        {
            "file": "pkg/b.py",
            "shared_commits": 1,
            "in_scope": True,
        }
    ]


def test_build_history_summary_ignores_malformed_numstat_lines() -> None:
    raw_text = "\n".join(
        [
            "commit a1",
            "1\t0\tpkg/tracked.py",
            "1\t0",
            "-\t0\tpkg/tracked.py",
            "x\t1\tpkg/tracked.py",
            "1\t0\tpkg/untracked.py",
            "",
        ]
    )

    summary = audit.build_history_summary(
        raw_text=raw_text,
        tracked_files={"pkg/tracked.py"},
        current_scope_files=["pkg/tracked.py"],
        min_shared_commits=1,
        coupling_ignore_commit_file_count=10,
        lookback_days=180,
    )

    assert summary["files"]["pkg/tracked.py"]["commit_frequency"] == 1
    assert summary["files"]["pkg/tracked.py"]["churn"] == 1
    assert summary["files"]["pkg/tracked.py"]["top_coupled_files"] == []


def test_history_collection_inputs_include_explicit_scope_files_outside_default_targets(
    tmp_path: Path,
) -> None:
    lookup = _lookup_for(tmp_path, "main.py")
    scope_state = audit.AuditScopeState(
        files=[tmp_path / "main.py"],
        current_scope_files=["main.py"],
        default_scope_files=("pkg/example.py",),
        is_partial_scope=True,
        lookup=lookup,
        raw_dir=tmp_path,
    )
    request = audit.RefactorAuditRunRequest(
        scope_targets=["main.py"],
        out_dir=tmp_path / "out",
        baseline_path=tmp_path / "baseline.json",
        update_baseline=False,
        fail_on_regression=False,
        lookback_days=CONFIG.history.lookback_days,
        coverage_json=CONFIG.coverage.coverage_json,
        config=CONFIG,
    )

    targets, tracked_files = core_engine._history_collection_inputs(
        request=request,
        scope_state=scope_state,
    )

    assert targets == [*CONFIG.targets, "main.py"]
    assert tracked_files == ("main.py", "pkg/example.py")


def test_load_coverage_summary_prefers_branch_then_line_then_unknown(tmp_path: Path) -> None:
    coverage_path = tmp_path / "coverage.json"
    coverage_path.write_text(json.dumps(_coverage_payload()), encoding="utf-8")

    coverage = audit.load_coverage_summary(
        coverage_json=coverage_path,
        repo_root=tmp_path,
        tracked_files={
            "pkg/branchy.py",
            "pkg/line_only.py",
            "pkg/unknown.py",
            "pkg/missing.py",
        },
    )

    assert coverage["status"] == "available"
    assert coverage["files"]["pkg/branchy.py"] == {
        "mode": "branch",
        "fraction": 0.75,
    }
    assert coverage["files"]["pkg/line_only.py"] == {
        "mode": "line",
        "fraction": 0.75,
    }
    assert coverage["files"]["pkg/unknown.py"] == {
        "mode": "unknown",
        "fraction": None,
    }
    assert coverage["files"]["pkg/missing.py"] == {
        "mode": "unknown",
        "fraction": None,
    }


def test_load_coverage_summary_resolves_absolute_file_paths(tmp_path: Path) -> None:
    absolute_path = tmp_path / "pkg" / "absolute.py"
    absolute_path.parent.mkdir(parents=True, exist_ok=True)
    absolute_path.write_text("pass\n", encoding="utf-8")
    coverage_path = tmp_path / "coverage.json"
    coverage_path.write_text(
        json.dumps(
            {
                "files": {
                    str(absolute_path.resolve()): {
                        "summary": {
                            "covered_lines": 3,
                            "num_statements": 4,
                        }
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    coverage = audit.load_coverage_summary(
        coverage_json=coverage_path,
        repo_root=tmp_path,
        tracked_files={"pkg/absolute.py"},
    )

    assert coverage["status"] == "available"
    assert coverage["files"]["pkg/absolute.py"] == {
        "mode": "line",
        "fraction": 0.75,
    }


def test_load_coverage_summary_returns_unavailable_for_non_mapping_files_section(
    tmp_path: Path,
) -> None:
    coverage_path = tmp_path / "coverage.json"
    coverage_path.write_text(json.dumps({"files": []}), encoding="utf-8")

    coverage = audit.load_coverage_summary(
        coverage_json=coverage_path,
        repo_root=tmp_path,
        tracked_files={"pkg/example.py"},
    )

    assert coverage["status"] == "unavailable"
    assert coverage["files"]["pkg/example.py"] == {
        "mode": "unknown",
        "fraction": None,
    }


def test_load_coverage_summary_ignores_non_mapping_entries_and_summaries(
    tmp_path: Path,
) -> None:
    coverage_path = tmp_path / "coverage.json"
    coverage_path.write_text(
        json.dumps(
            {
                "files": {
                    "pkg/not_a_mapping.py": [],
                    "pkg/not_a_summary.py": {"summary": []},
                }
            }
        ),
        encoding="utf-8",
    )

    coverage = audit.load_coverage_summary(
        coverage_json=coverage_path,
        repo_root=tmp_path,
        tracked_files={"pkg/not_a_mapping.py", "pkg/not_a_summary.py"},
    )

    assert coverage["status"] == "available"
    assert coverage["files"]["pkg/not_a_mapping.py"] == {
        "mode": "unknown",
        "fraction": None,
    }
    assert coverage["files"]["pkg/not_a_summary.py"] == {
        "mode": "unknown",
        "fraction": None,
    }


def test_coerce_refactor_audit_run_request_uses_config_defaults_for_legacy_kwargs(
    tmp_path: Path,
) -> None:
    config = replace(
        CONFIG,
        coverage=audit.CoverageConfig(coverage_json=tmp_path / "coverage.json"),
    )

    request = core_engine._coerce_refactor_audit_run_request(
        legacy_kwargs={
            "scope_targets": ["src/cremona/scan.py"],
            "out_dir": tmp_path / "out",
            "baseline_path": tmp_path / "baseline.json",
            "update_baseline": False,
            "fail_on_regression": False,
            "config": config,
        }
    )

    assert request.lookback_days == config.history.lookback_days
    assert request.coverage_json == config.coverage.coverage_json


def test_build_agent_routing_index_detects_builtin_and_declared_signals(
    tmp_path: Path,
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[tool.cremona]
profile = "workflow-app"

[tool.cremona.profiles.workflow-app]
base = "generic-python"
fallback_subsystem = "other"

[[tool.cremona.profiles.workflow-app.signals]]
name = "kwargs_bridge_hits"
kind = "regex_count"
pattern = '\\blegacy_[A-Za-z0-9_]*\\b'
points_per = 10
max_points = 6

[[tool.cremona.profiles.workflow-app.signals]]
name = "request_wrapper"
kind = "regex_flag"
pattern = 'request\\s*:\\s*[^=\\n]+?\\|\\s*None\\s*=\\s*None'
points = 2
""".strip()
        + "\n",
        encoding="utf-8",
    )
    config = audit.load_audit_config(repo_root=tmp_path)
    profile = audit.get_profile("workflow-app", config.profile_registry)
    shadow_module = tmp_path / "pkg" / "cli.py"
    shadow_module.parent.mkdir(parents=True, exist_ok=True)
    shadow_module.write_text(
        "from pkg.cli import *\n",
        encoding="utf-8",
    )
    shadow_package = tmp_path / "pkg" / "cli"
    shadow_package.mkdir()
    (shadow_package / "__init__.py").write_text("", encoding="utf-8")

    facade_path = tmp_path / "pkg" / "storage.py"
    facade_path.write_text(
        """
from pkg.storage.facade import Repository

__all__ = ["Repository"]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    facade_dir = tmp_path / "pkg" / "storage"
    facade_dir.mkdir()
    (facade_dir / "__init__.py").write_text("", encoding="utf-8")

    compat_path = tmp_path / "pkg" / "translate.py"
    compat_path.write_text(
        """
from __future__ import annotations
from typing import Any


def wrapper(*, request: object | None = None, **legacy_kwargs: Any) -> object:
    return request or legacy_kwargs
""".strip()
        + "\n",
        encoding="utf-8",
    )

    with _use_profile(profile):
        index = audit.build_agent_routing_index(
            repo_root=tmp_path,
            files=[shadow_module, facade_path, compat_path],
        )

    assert index["pkg/cli.py"]["module_package_shadow"] == 1
    assert index["pkg/cli.py"]["wildcard_reexport"] == 1
    assert index["pkg/storage.py"]["facade_reexport"] == 1
    assert index["pkg/translate.py"]["kwargs_bridge_hits"] >= 2
    assert index["pkg/translate.py"]["request_wrapper"] == 1


def test_generic_python_profile_uses_top_level_dir_as_subsystem() -> None:
    assert audit.infer_subsystem("pkg/cli.py") == "pkg"


def test_generic_python_profile_scans_non_generic_fixture_end_to_end(
    tmp_path: Path,
) -> None:
    fixture_root = tmp_path / "generic_project"
    src_dir = fixture_root / "src" / "demo"
    tests_dir = fixture_root / "tests"
    src_dir.mkdir(parents=True)
    tests_dir.mkdir(parents=True)
    (fixture_root / "pyproject.toml").write_text(
        """
[tool.cremona]
profile = "generic-python"
targets = ["src", "tests"]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (src_dir / "__init__.py").write_text("", encoding="utf-8")
    (src_dir / "hotspot.py").write_text(
        """
from __future__ import annotations


def branchy(a: bool, b: bool, c: bool, d: bool, e: bool, f: bool) -> int:
    total = 0
    if a:
        total += 1
    if b:
        total += 1
    if c:
        total += 1
    if d:
        total += 1
    if e:
        total += 1
    if f:
        total += 1
    if a and b:
        total += 1
    if c and d:
        total += 1
    if e and f:
        total += 1
    if a or c:
        total += 1
    if b or d:
        total += 1
    if e or a:
        total += 1
    return total
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (tests_dir / "test_smoke.py").write_text(
        """
def test_smoke() -> None:
    assert True
""".strip()
        + "\n",
        encoding="utf-8",
    )

    report = audit.run_scan(
        audit.ScanRequest(
            scope_targets=[str(fixture_root / "src"), str(fixture_root / "tests")],
            out_dir=tmp_path / "audit-out",
            baseline_path=tmp_path / "baseline.json",
            profile="generic-python",
        )
    )

    subsystems = {item["subsystem"] for item in report["agent_routing_queue"]}
    assert report.exit_code == 0
    assert subsystems <= {"src", "tests"}
    assert "src" in subsystems
    assert not (subsystems & {"cli", "pipeline", "storage", "rag", "site/render"})
    assert any(group["subsystem"] == "src" for group in report["recommended_queue"])
    assert (tmp_path / "audit-out" / "report.json").exists()


def test_run_scan_cli_profile_override_beats_repo_default(tmp_path: Path) -> None:
    fixture_root = tmp_path / "workflow_project"
    cli_dir = fixture_root / "app" / "cli"
    cli_dir.mkdir(parents=True)
    (fixture_root / "pyproject.toml").write_text(
        """
[tool.cremona]
profile = "workflow-app"
targets = ["app"]

[tool.cremona.profiles.workflow-app]
base = "generic-python"
queue_order = ["cli", "other"]
fallback_subsystem = "other"

[[tool.cremona.profiles.workflow-app.subsystems]]
name = "cli"
include = ["app/cli/**"]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (cli_dir / "hotspot.py").write_text(
        """
from __future__ import annotations


def branchy(a: bool, b: bool, c: bool, d: bool, e: bool, f: bool) -> int:
    total = 0
    if a:
        total += 1
    if b:
        total += 1
    if c:
        total += 1
    if d:
        total += 1
    if e:
        total += 1
    if f:
        total += 1
    if a and b:
        total += 1
    if c and d:
        total += 1
    if e and f:
        total += 1
    if a or c:
        total += 1
    if b or d:
        total += 1
    if e or a:
        total += 1
    return total
""".strip()
        + "\n",
        encoding="utf-8",
    )

    config = audit.load_audit_config(repo_root=fixture_root)
    report = audit.run_scan(
        audit.ScanRequest(
            scope_targets=[str(fixture_root / "app")],
            out_dir=tmp_path / "audit-out",
            baseline_path=tmp_path / "baseline.json",
            config=config,
            profile="generic-python",
        )
    )

    assert report.exit_code == 0
    assert report["agent_routing_queue"][0]["subsystem"] == "app"
    assert report["recommended_queue"][0]["subsystem"] == "src"


def test_build_agent_routing_queue_prioritizes_high_churn_ambiguous_file() -> None:
    queue = audit.build_agent_routing_queue(
        scope_files=["pkg/cli.py", "pkg/example.py"],
        hotspots=[
            {
                "id": "pkg/example.py::branchy",
                "file": "pkg/example.py",
                "symbol": "branchy",
                "classification": "monitor",
                "subsystem": "other",
                "tool_count": 1,
                "tools": ["ruff"],
                "metrics": {"ruff": {"complexity": 12}},
            }
        ],
        dead_code_candidates=[
            {
                "id": "pkg/cli.py::function::legacy_entrypoint",
                "file": "pkg/cli.py",
                "symbol": "legacy_entrypoint",
                "classification": "review_candidate",
                "confidence": 60,
                "kind": "function",
            }
        ],
        history_summary={
            "status": "available",
            "max_commit_frequency": 10,
            "max_churn": 500,
            "files": {
                "pkg/cli.py": {
                    "commit_frequency": 10,
                    "churn": 500,
                    "top_coupled_files": [
                        {
                            "file": "pkg/cli/app.py",
                            "shared_commits": 4,
                            "in_scope": False,
                        }
                    ],
                },
                "pkg/example.py": {
                    "commit_frequency": 1,
                    "churn": 10,
                    "top_coupled_files": [],
                },
            },
        },
        coverage_summary={
            "status": "available",
            "files": {
                "pkg/cli.py": {"mode": "unknown", "fraction": None},
                "pkg/example.py": {"mode": "branch", "fraction": 0.9},
            },
        },
        routing_index={
            "pkg/cli.py": {
                "module_package_shadow": 1,
                "wildcard_reexport": 1,
                "facade_reexport": 0,
            },
            "pkg/example.py": {
                "module_package_shadow": 0,
                "wildcard_reexport": 0,
                "facade_reexport": 0,
            },
        },
    )

    assert queue[0]["file"] == "pkg/cli.py"
    assert queue[0]["priority_band"] in {"investigate_now", "investigate_soon"}
    assert queue[0]["dead_code_candidate_count"] == 1
    assert queue[1]["file"] == "pkg/example.py"
    assert queue[1]["hotspot_summary"]["monitor"] == 1


def test_build_agent_routing_queue_raises_refactor_now_file_to_investigate_soon() -> None:
    queue = audit.build_agent_routing_queue(
        scope_files=["pkg/refactor_now.py", "pkg/churny.py"],
        hotspots=[
            {
                "id": "pkg/refactor_now.py::branchy",
                "file": "pkg/refactor_now.py",
                "symbol": "branchy",
                "classification": "refactor_now",
                "subsystem": "other",
                "tool_count": 2,
                "tools": ["lizard", "complexipy"],
                "metrics": {
                    "lizard": {"ccn": 31, "nloc": 120, "parameter_count": 4},
                    "complexipy": {"complexity": 55},
                },
            }
        ],
        dead_code_candidates=[],
        history_summary={
            "status": "available",
            "max_commit_frequency": 10,
            "max_churn": 1000,
            "files": {
                "pkg/refactor_now.py": {
                    "commit_frequency": 1,
                    "churn": 10,
                    "top_coupled_files": [],
                },
                "pkg/churny.py": {
                    "commit_frequency": 10,
                    "churn": 1000,
                    "top_coupled_files": [
                        {
                            "file": "pkg/churny_helpers.py",
                            "shared_commits": 4,
                            "in_scope": False,
                        }
                    ],
                },
            },
        },
        coverage_summary={
            "status": "available",
            "files": {
                "pkg/refactor_now.py": {"mode": "branch", "fraction": 0.95},
                "pkg/churny.py": {"mode": "branch", "fraction": 0.95},
            },
        },
        routing_index={
            "pkg/refactor_now.py": {
                "module_package_shadow": 0,
                "wildcard_reexport": 0,
                "facade_reexport": 0,
            },
            "pkg/churny.py": {
                "module_package_shadow": 0,
                "wildcard_reexport": 0,
                "facade_reexport": 0,
            },
        },
    )

    refactor_now_file = next(
        item for item in queue if item["file"] == "pkg/refactor_now.py"
    )
    churny_file = next(item for item in queue if item["file"] == "pkg/churny.py")

    assert refactor_now_file["priority_score"] == 35
    assert refactor_now_file["priority_band"] == "investigate_soon"
    assert churny_file["priority_band"] in {"investigate_now", "investigate_soon"}


def test_build_agent_routing_queue_applies_declared_routing_bonus_rules(
    tmp_path: Path,
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[tool.cremona]
profile = "workflow-app"

[tool.cremona.profiles.workflow-app]
base = "generic-python"
fallback_subsystem = "other"

[[tool.cremona.profiles.workflow-app.signals]]
name = "kwargs_bridge_hits"
kind = "regex_count"
pattern = "\\blegacy_[A-Za-z0-9_]*\\b"
points_per = 10
max_points = 6

[[tool.cremona.profiles.workflow-app.routing_bonuses]]
name = "migration_pressure"
points = 4
all = [
  { source = "signal", name = "kwargs_bridge_hits", op = ">=", value = 25 },
  { source = "component", name = "coupling_score", op = ">=", value = 10 },
]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    config = audit.load_audit_config(repo_root=tmp_path)
    profile = audit.get_profile("workflow-app", config.profile_registry)

    with _use_profile(profile):
        queue = audit.build_agent_routing_queue(
            scope_files=["pkg/translation.py", "pkg/example.py"],
            hotspots=[],
            dead_code_candidates=[],
            history_summary={
                "status": "available",
                "max_commit_frequency": 20,
                "max_churn": 1000,
                "files": {
                    "pkg/translation.py": {
                        "commit_frequency": 18,
                        "churn": 600,
                        "top_coupled_files": [
                            {"file": "pkg/cli/app.py", "shared_commits": 7, "in_scope": False},
                            {"file": "pkg/cli/translate.py", "shared_commits": 7, "in_scope": False},
                            {"file": "pkg/materialize.py", "shared_commits": 7, "in_scope": False},
                            {"file": "pkg/trends.py", "shared_commits": 7, "in_scope": False},
                            {
                                "file": "pkg/pipeline/trends_stage.py",
                                "shared_commits": 6,
                                "in_scope": False,
                            },
                        ],
                    },
                    "pkg/example.py": {
                        "commit_frequency": 1,
                        "churn": 10,
                        "top_coupled_files": [],
                    },
                },
            },
            coverage_summary={
                "status": "unavailable",
                "files": {
                    "pkg/translation.py": {"mode": "unknown", "fraction": None},
                    "pkg/example.py": {"mode": "unknown", "fraction": None},
                },
            },
            routing_index={
                "pkg/translation.py": {
                    "module_package_shadow": 0,
                    "wildcard_reexport": 0,
                    "facade_reexport": 0,
                    "kwargs_bridge_hits": 80,
                },
                "pkg/example.py": {
                    "module_package_shadow": 0,
                    "wildcard_reexport": 0,
                    "facade_reexport": 0,
                    "kwargs_bridge_hits": 0,
                },
            },
        )

    assert queue[0]["file"] == "pkg/translation.py"
    assert queue[0]["priority_band"] == "investigate_soon"
    assert queue[0]["priority_components"]["routing_bonus_score"] > 0
    assert queue[0]["routing_rules_triggered"] == ["migration_pressure"]


def test_build_agent_routing_queue_applies_subsystem_priority_offsets(
    tmp_path: Path,
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[tool.cremona]
profile = "workflow-app"

[tool.cremona.profiles.workflow-app]
base = "generic-python"
subsystem_priority_offsets = { tests = -10 }
""".strip()
        + "\n",
        encoding="utf-8",
    )
    config = audit.load_audit_config(repo_root=tmp_path)
    profile = audit.get_profile("workflow-app", config.profile_registry)

    with _use_profile(profile):
        queue = audit.build_agent_routing_queue(
            scope_files=["src/core.py", "tests/test_core.py"],
            hotspots=[],
            dead_code_candidates=[],
            history_summary={
                "status": "available",
                "max_commit_frequency": 10,
                "max_churn": 500,
                "files": {
                    "src/core.py": {
                        "commit_frequency": 4,
                        "churn": 200,
                        "top_coupled_files": [],
                    },
                    "tests/test_core.py": {
                        "commit_frequency": 6,
                        "churn": 250,
                        "top_coupled_files": [],
                    },
                },
            },
            coverage_summary={
                "status": "available",
                "files": {
                    "src/core.py": {"mode": "branch", "fraction": 0.9},
                    "tests/test_core.py": {"mode": "branch", "fraction": 1.0},
                },
            },
            routing_index={
                "src/core.py": {
                    "module_package_shadow": 0,
                    "wildcard_reexport": 0,
                    "facade_reexport": 0,
                },
                "tests/test_core.py": {
                    "module_package_shadow": 0,
                    "wildcard_reexport": 0,
                    "facade_reexport": 0,
                },
            },
        )

    assert queue[0]["file"] == "src/core.py"
    assert queue[1]["file"] == "tests/test_core.py"
    assert queue[1]["priority_components"]["subsystem_priority_score"] == -10


def test_build_repo_verdict_reports_routing_pressure_separately_from_debt_status() -> None:
    verdict = audit.build_repo_verdict(
        hotspots=[
            {
                "classification": "monitor",
            }
        ],
        baseline_diff={"has_regressions": False, "new": []},
        agent_routing_queue=[
            {
                "priority_band": "investigate_soon",
                "coverage": {"mode": "unknown", "fraction": None},
            }
        ],
        history_summary={"status": "available"},
    )

    assert verdict["status"] == "stable"
    assert verdict["debt_status"] == "stable"
    assert verdict["routing_pressure"] == "investigate_soon"
    assert "Routing pressure is investigate_soon" in verdict["summary"]


def test_build_repo_verdict_marks_missing_coverage_as_partial_signal_health() -> None:
    verdict = audit.build_repo_verdict(
        hotspots=[],
        baseline_diff={"has_regressions": False, "new": []},
        agent_routing_queue=[
            {
                "priority_band": "watch",
                "coverage": {"mode": "unknown", "fraction": None},
            }
        ],
        history_summary={"status": "available"},
    )

    assert verdict["status"] == "stable"
    assert verdict["signal_health"] == "partial"
    assert verdict["missing_signals"] == ["coverage"]
    assert "missing coverage" in verdict["summary"]


def test_build_repo_verdict_marks_sparse_coverage_as_partial_signal_health() -> None:
    verdict = audit.build_repo_verdict(
        hotspots=[],
        baseline_diff={"has_regressions": False, "new": []},
        agent_routing_queue=[
            {
                "priority_band": "watch",
                "coverage": {"mode": "branch", "fraction": 0.8},
            },
            {
                "priority_band": "watch",
                "coverage": {"mode": "unknown", "fraction": None},
            },
        ],
        history_summary={"status": "available"},
    )

    assert verdict["status"] == "stable"
    assert verdict["signal_health"] == "partial"
    assert verdict["missing_signals"] == ["coverage"]
    assert "missing coverage" in verdict["summary"]


def test_build_repo_verdict_marks_existing_refactor_soon_debt_as_strained() -> None:
    verdict = audit.build_repo_verdict(
        hotspots=[
            {
                "classification": "refactor_soon",
            }
        ],
        baseline_diff={"has_regressions": False, "new": []},
        agent_routing_queue=[],
        history_summary={"status": "available"},
    )

    assert verdict["status"] == "strained"
    assert verdict["debt_status"] == "strained"
    assert "Existing structural debt remains" in verdict["summary"]


def test_build_repo_verdict_treats_new_refactor_now_hotspot_as_corroding() -> None:
    verdict = audit.build_repo_verdict(
        hotspots=[],
        baseline_diff={
            "has_regressions": False,
            "new": [
                {
                    "kind": "hotspot",
                    "after": {"classification": "refactor_now"},
                }
            ],
        },
        agent_routing_queue=[],
        history_summary={"status": "available"},
    )

    assert verdict["status"] == "corroding"
    assert verdict["debt_status"] == "corroding"
    assert "Structural debt is regressing" in verdict["summary"]


def test_build_baseline_diff_marks_new_hotspots() -> None:
    current_hotspots = [
        {
            "id": "pkg/example.py::branchy",
            "file": "pkg/example.py",
            "symbol": "branchy",
            "classification": "refactor_soon",
            "tools": ["ruff"],
            "metrics": {"ruff": {"complexity": 16}},
        }
    ]

    diff = audit.build_baseline_diff(
        current_hotspots=current_hotspots,
        current_dead_code_candidates=[],
        baseline_report={
            "schema_version": 3,
            "hotspots": [],
            "dead_code_candidates": [],
        },
        scope_files=["pkg/example.py"],
        config=CONFIG,
    )

    assert diff["new"][0]["kind"] == "hotspot"
    assert diff["new"][0]["symbol"] == "branchy"


def test_build_baseline_diff_marks_worsened_hotspots() -> None:
    baseline_report = {
        "schema_version": 3,
        "hotspots": [
            {
                "id": "pkg/example.py::branchy",
                "file": "pkg/example.py",
                "symbol": "branchy",
                "classification": "monitor",
                "tools": ["ruff"],
                "metrics": {"ruff": {"complexity": 12}},
            }
        ],
        "dead_code_candidates": [],
    }
    current_hotspots = [
        {
            "id": "pkg/example.py::branchy",
            "file": "pkg/example.py",
            "symbol": "branchy",
            "classification": "refactor_soon",
            "tools": ["ruff", "lizard"],
            "metrics": {
                "ruff": {"complexity": 16},
                "lizard": {"ccn": 18, "nloc": 90, "parameter_count": 4},
            },
        }
    ]

    diff = audit.build_baseline_diff(
        current_hotspots=current_hotspots,
        current_dead_code_candidates=[],
        baseline_report=baseline_report,
        scope_files=["pkg/example.py"],
        config=CONFIG,
    )

    assert diff["worsened"][0]["kind"] == "hotspot"
    assert "classification" in diff["worsened"][0]["reasons"]


def test_build_baseline_diff_ignores_same_band_lizard_nloc_growth() -> None:
    baseline_report = {
        "schema_version": 3,
        "hotspots": [
            {
                "id": "pkg/example.py::branchy",
                "file": "pkg/example.py",
                "symbol": "branchy",
                "classification": "monitor",
                "tools": ["lizard"],
                "metrics": {"lizard": {"ccn": 10, "nloc": 117, "parameter_count": 4}},
            }
        ],
        "dead_code_candidates": [],
    }
    current_hotspots = [
        {
            "id": "pkg/example.py::branchy",
            "file": "pkg/example.py",
            "symbol": "branchy",
            "classification": "monitor",
            "tools": ["lizard"],
            "metrics": {"lizard": {"ccn": 10, "nloc": 125, "parameter_count": 4}},
        }
    ]

    diff = audit.build_baseline_diff(
        current_hotspots=current_hotspots,
        current_dead_code_candidates=[],
        baseline_report=baseline_report,
        scope_files=["pkg/example.py"],
        config=CONFIG,
    )

    assert diff["has_regressions"] is False
    assert diff["worsened"] == []


def test_build_baseline_diff_ignores_new_monitor_lizard_nloc_hotspot() -> None:
    current_hotspots = [
        {
            "id": "pkg/example.py::wrapped",
            "file": "pkg/example.py",
            "symbol": "wrapped",
            "classification": "monitor",
            "tools": ["lizard"],
            "metrics": {"lizard": {"ccn": 8, "nloc": 102, "parameter_count": 3}},
        }
    ]

    diff = audit.build_baseline_diff(
        current_hotspots=current_hotspots,
        current_dead_code_candidates=[],
        baseline_report={
            "schema_version": 3,
            "hotspots": [],
            "dead_code_candidates": [],
        },
        scope_files=["pkg/example.py"],
        config=CONFIG,
    )

    assert diff["has_regressions"] is False
    assert diff["new"] == []


def test_build_baseline_diff_marks_resolved_hotspots() -> None:
    baseline_report = {
        "schema_version": 3,
        "hotspots": [
            {
                "id": "pkg/example.py::branchy",
                "file": "pkg/example.py",
                "symbol": "branchy",
                "classification": "refactor_soon",
                "tools": ["ruff"],
                "metrics": {"ruff": {"complexity": 16}},
            }
        ],
        "dead_code_candidates": [],
    }

    diff = audit.build_baseline_diff(
        current_hotspots=[],
        current_dead_code_candidates=[],
        baseline_report=baseline_report,
        scope_files=["pkg/example.py"],
        config=CONFIG,
    )

    assert diff["resolved"][0]["kind"] == "hotspot"
    assert diff["resolved"][0]["symbol"] == "branchy"


def test_render_markdown_report_contains_required_sections() -> None:
    report = make_report(
        summary=make_summary(
            files_scanned=1,
            hotspots_total=1,
            refactor_soon_total=1,
            agent_routing_queue_total=1,
            investigate_soon_total=1,
            dead_code_candidates_total=1,
            dead_code_high_confidence_total=1,
        ),
        repo_verdict=make_repo_verdict(
            status="strained",
            debt_status="strained",
            routing_pressure="investigate_soon",
            summary=(
                "Existing structural debt remains, but the current scope did not regress. "
                "Routing pressure is investigate_soon. Signal health is partial: missing coverage."
            ),
            signal_health="partial",
            missing_signals=["coverage"],
        ),
        tool_summaries=make_tool_summaries(
            ruff={"findings_total": 1, "warning": 1, "high": 0, "critical": 0},
            lizard={"findings_total": 1, "warning": 1, "high": 0, "critical": 0},
            vulture={
                "findings_total": 1,
                "review_candidate": 0,
                "high_confidence_candidate": 1,
            },
        ),
        hotspots=[
            make_hotspot(
                classification="refactor_soon",
                tools=["lizard", "ruff"],
                metrics={
                    "lizard": {"ccn": 18, "nloc": 90, "parameter_count": 4},
                    "ruff": {"complexity": 16},
                },
            )
        ],
        dead_code_candidates=[make_dead_code_candidate()],
        agent_routing_queue=[
            make_routing_item(
                priority_score=40,
                priority_band="investigate_soon",
                change_frequency=4,
                churn=20,
                coverage={"mode": "branch", "fraction": 0.8},
            )
        ],
        baseline_diff=make_baseline_diff(),
        recommended_refactor_queue=[
            {"subsystem": "pipeline", "investigate_now": 0, "investigate_soon": 0, "watch": 0},
            {"subsystem": "other", "investigate_now": 0, "investigate_soon": 1, "watch": 0},
        ],
    )

    markdown = audit.render_markdown_report(report)

    assert "Repo verdict" in markdown
    assert "Debt status" in markdown
    assert "Routing pressure" in markdown
    assert "Signal health" in markdown
    assert "Missing signals: coverage" in markdown
    assert "Agent routing queue" in markdown
    assert "Top hotspots" in markdown
    assert "Dead code candidates" in markdown
    assert "Recommended refactor queue" in markdown


def test_build_baseline_snapshot_resets_diff_and_repo_verdict() -> None:
    report = make_report(
        summary=make_summary(files_scanned=1, hotspots_total=1, refactor_soon_total=1),
        repo_verdict=make_repo_verdict(
            status="corroding",
            debt_status="corroding",
            summary="Structural debt is regressing in the current scope.",
            has_regressions=True,
        ),
        hotspots=[
            make_hotspot(
                classification="refactor_soon",
                metrics={"ruff": {"complexity": 16}},
            )
        ],
        baseline_diff=make_baseline_diff(
            has_regressions=True,
            new=[{"kind": "hotspot"}],
        ),
    )

    snapshot = audit.build_baseline_snapshot(report)

    assert snapshot["baseline_diff"]["baseline_available"] is False
    assert snapshot["baseline_diff"]["has_regressions"] is False
    assert snapshot["baseline_diff"]["new"] == []
    assert snapshot["history_summary"]["status"] == "available"
    assert snapshot["agent_routing_queue"] == []
    assert snapshot["repo_verdict"]["status"] == "strained"


def test_build_baseline_snapshot_preserves_out_of_scope_records() -> None:
    baseline_report, report = _partial_scope_snapshot_inputs()
    snapshot = audit.build_baseline_snapshot(
        report,
        baseline_report=baseline_report,
        scope_files=["pkg/in_scope.py"],
    )

    assert [item["id"] for item in snapshot["hotspots"]] == [
        "pkg/out_of_scope.py::other_hotspot",
        "pkg/in_scope.py::branchy",
    ]
    assert snapshot["dead_code_candidates"][0]["file"] == "pkg/out_of_scope.py"
    assert [item["file"] for item in snapshot["agent_routing_queue"]] == [
        "pkg/out_of_scope.py",
        "pkg/in_scope.py",
    ]
    assert snapshot["history_summary"]["files"]["pkg/out_of_scope.py"]["churn"] == 100


def test_build_baseline_snapshot_recomputes_summary_and_tool_summaries_after_partial_merge() -> None:
    baseline_report, report = _partial_scope_snapshot_inputs()
    snapshot = audit.build_baseline_snapshot(
        report,
        baseline_report=baseline_report,
        scope_files=["pkg/in_scope.py"],
    )

    assert snapshot["summary"]["files_scanned"] == 2
    assert snapshot["summary"]["hotspots_total"] == 2
    assert snapshot["tool_summaries"]["ruff"]["critical"] == 1
    assert snapshot["tool_summaries"]["complexipy"]["critical"] == 1
    assert snapshot["baseline_diff"]["has_regressions"] is False


def test_build_baseline_snapshot_rebuilds_recommended_queue_after_partial_merge() -> None:
    baseline_report, report = _partial_scope_snapshot_inputs()
    snapshot = audit.build_baseline_snapshot(
        report,
        baseline_report=baseline_report,
        scope_files=["pkg/in_scope.py"],
    )

    recommended_other = next(
        item for item in snapshot["recommended_queue"] if item["subsystem"] == "other"
    )
    assert recommended_other["investigate_now"] == 1
    assert recommended_other["investigate_soon"] == 1
    assert snapshot["recommended_queue"] == snapshot["recommended_refactor_queue"]


def test_build_baseline_snapshot_recomputes_history_extrema_after_partial_merge() -> None:
    baseline_report, report = _partial_scope_snapshot_inputs()
    snapshot = audit.build_baseline_snapshot(
        report,
        baseline_report=baseline_report,
        scope_files=["pkg/in_scope.py"],
    )

    assert snapshot["history_summary"]["max_commit_frequency"] == 8
    assert snapshot["history_summary"]["max_churn"] == 100


def test_build_baseline_snapshot_rejects_legacy_baseline_schema() -> None:
    baseline_report = {
        "schema_version": 2,
        "scope": make_scope(
            files=["pkg/in_scope.py", "pkg/out_of_scope.py"],
            file_count=2,
        ),
        "hotspots": [],
        "dead_code_candidates": [],
    }
    report = make_report(
        summary=make_summary(
            files_scanned=1,
            agent_routing_queue_total=1,
            watch_total=1,
        ),
        agent_routing_queue=[
            make_routing_item(
                file="pkg/in_scope.py",
                subsystem="other",
                priority_score=20,
                priority_band="watch",
                change_frequency=1,
                churn=2,
            )
        ],
        history_summary=make_history_summary(
            max_commit_frequency=1,
            max_churn=2,
            files={
                "pkg/in_scope.py": {
                    "commit_frequency": 1,
                    "churn": 2,
                    "top_coupled_files": [],
                }
            },
        ),
        baseline_diff=make_baseline_diff(),
        scope=make_scope(files=["pkg/in_scope.py"], file_count=1),
    )

    try:
        audit.build_baseline_snapshot(
            report,
            baseline_report=baseline_report,
            scope_files=["pkg/in_scope.py"],
        )
    except RuntimeError as exc:
        message = str(exc)
    else:
        raise AssertionError("Expected legacy baseline schema to be rejected")

    assert "schema version" in message
    assert "Regenerate the baseline" in message


def test_refactor_audit_cli_generates_schema_stable_outputs(tmp_path: Path) -> None:
    fixture_root = tmp_path / "fixture_project"
    fixture_root.mkdir()
    package_dir = fixture_root / "fixture_pkg"
    package_dir.mkdir()
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "hotspot.py").write_text(
        """
from __future__ import annotations


def branchy(a: bool, b: bool, c: bool, d: bool, e: bool, f: bool) -> int:
    total = 0
    if a:
        total += 1
    if b:
        total += 1
    if c:
        total += 1
    if d:
        total += 1
    if e:
        total += 1
    if f:
        total += 1
    if a and b:
        total += 1
    if c and d:
        total += 1
    if e and f:
        total += 1
    if a or c:
        total += 1
    if b or d:
        total += 1
    if e or a:
        total += 1
    return total


def unused_helper() -> str:
    return "unused"
""".strip()
        + "\n",
        encoding="utf-8",
    )

    out_dir = tmp_path / "audit-out"
    baseline_path = tmp_path / "baseline.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "cremona.cli",
            "scan",
            ".",
            "--out-dir",
            str(out_dir),
            "--baseline",
            str(baseline_path),
        ],
        cwd=fixture_root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr or result.stdout

    report_json = out_dir / "report.json"
    report_md = out_dir / "report.md"
    assert report_json.exists()
    assert report_md.exists()
    assert (out_dir / "raw" / "ruff.json").exists()
    assert (out_dir / "raw" / "lizard.csv").exists()
    assert (out_dir / "raw" / "complexipy.json").exists()
    assert (out_dir / "raw" / "vulture.txt").exists()

    payload = json.loads(report_json.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 3
    assert payload["scope"]["file_count"] == 2
    assert set(payload) >= {
        "schema_version",
        "generated_at",
        "scope",
        "summary",
        "repo_verdict",
        "history_summary",
        "tool_summaries",
        "hotspots",
        "dead_code_candidates",
        "agent_routing_queue",
        "baseline_diff",
        "recommended_queue",
        "recommended_refactor_queue",
    }
    assert payload["hotspots"]
    assert payload["dead_code_candidates"] == []


def test_refactor_audit_cli_bootstraps_baseline_from_repo_config(tmp_path: Path) -> None:
    fixture_root = tmp_path / "fixture_project"
    fixture_root.mkdir()
    source_dir = fixture_root / "src"
    source_dir.mkdir()
    tests_dir = fixture_root / "tests"
    tests_dir.mkdir()
    (source_dir / "hotspot.py").write_text(
        """
from __future__ import annotations


def branchy(a: bool, b: bool, c: bool, d: bool, e: bool, f: bool) -> int:
    total = 0
    if a:
        total += 1
    if b:
        total += 1
    if c:
        total += 1
    if d:
        total += 1
    if e:
        total += 1
    if f:
        total += 1
    if a and b:
        total += 1
    if c and d:
        total += 1
    if e and f:
        total += 1
    if a or c:
        total += 1
    if b or d:
        total += 1
    if e or a:
        total += 1
    return total
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (tests_dir / "test_placeholder.py").write_text(
        """
def test_placeholder() -> None:
    assert True
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (fixture_root / "pyproject.toml").write_text(
        """
[tool.cremona]
targets = ["src", "tests"]
out_dir = "output/refactor-audit"
baseline = "quality/refactor-baseline.json"
""".strip()
        + "\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "cremona.cli",
            "scan",
            "--update-baseline",
        ],
        cwd=fixture_root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr or result.stdout

    report_json = fixture_root / "output" / "refactor-audit" / "report.json"
    baseline_path = fixture_root / "quality" / "refactor-baseline.json"
    assert report_json.exists()
    assert baseline_path.exists()

    report = json.loads(report_json.read_text(encoding="utf-8"))
    assert report["scope"]["requested_targets"] == ["src", "tests"]
    assert report["scope"]["file_count"] == 2

    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert baseline["scope"]["requested_targets"] == ["src", "tests"]
    assert baseline["scope"]["file_count"] == 2
    assert baseline["baseline_diff"]["baseline_available"] is False
    assert baseline["baseline_diff"]["has_regressions"] is False


def test_refactor_audit_cli_rejects_legacy_baseline_schema(tmp_path: Path) -> None:
    fixture_root = tmp_path / "fixture_project"
    fixture_root.mkdir()
    source_dir = fixture_root / "src"
    source_dir.mkdir()
    (source_dir / "hotspot.py").write_text(
        """
from __future__ import annotations


def branchy(a: bool, b: bool, c: bool, d: bool, e: bool, f: bool) -> int:
    total = 0
    if a:
        total += 1
    if b:
        total += 1
    if c:
        total += 1
    if d:
        total += 1
    if e:
        total += 1
    if f:
        total += 1
    if a and b:
        total += 1
    if c and d:
        total += 1
    if e and f:
        total += 1
    if a or c:
        total += 1
    if b or d:
        total += 1
    if e or a:
        total += 1
    return total
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (fixture_root / "pyproject.toml").write_text(
        """
[tool.cremona]
targets = ["src"]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    baseline_path = fixture_root / "quality" / "refactor-baseline.json"
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(
        json.dumps({"schema_version": 2, "hotspots": [], "dead_code_candidates": []}),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "cremona.cli",
            "scan",
            "--baseline",
            str(baseline_path),
        ],
        cwd=fixture_root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "Regenerate the baseline" in result.stderr
    assert "schema version" in result.stderr


def test_refactor_audit_cli_update_baseline_replaces_legacy_baseline_schema(
    tmp_path: Path,
) -> None:
    fixture_root = tmp_path / "fixture_project"
    fixture_root.mkdir()
    source_dir = fixture_root / "src"
    source_dir.mkdir()
    (source_dir / "hotspot.py").write_text(
        """
from __future__ import annotations


def branchy(a: bool, b: bool, c: bool, d: bool, e: bool, f: bool) -> int:
    total = 0
    if a:
        total += 1
    if b:
        total += 1
    if c:
        total += 1
    if d:
        total += 1
    if e:
        total += 1
    if f:
        total += 1
    if a and b:
        total += 1
    if c and d:
        total += 1
    if e and f:
        total += 1
    if a or c:
        total += 1
    if b or d:
        total += 1
    if e or a:
        total += 1
    return total
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (fixture_root / "pyproject.toml").write_text(
        """
[tool.cremona]
targets = ["src"]
baseline = "quality/refactor-baseline.json"
""".strip()
        + "\n",
        encoding="utf-8",
    )
    baseline_path = fixture_root / "quality" / "refactor-baseline.json"
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(
        json.dumps({"schema_version": 2, "hotspots": [], "dead_code_candidates": []}),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "cremona.cli",
            "scan",
            "--update-baseline",
        ],
        cwd=fixture_root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr or result.stdout

    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert baseline["schema_version"] == 3
    assert baseline["baseline_diff"]["baseline_available"] is False


def test_refactor_audit_cli_rejects_partial_baseline_init(tmp_path: Path) -> None:
    fixture_root = tmp_path / "fixture_project"
    fixture_root.mkdir()
    package_dir = fixture_root / "fixture_pkg"
    package_dir.mkdir()
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    hotspot_path = package_dir / "hotspot.py"
    hotspot_path.write_text(
        """
from __future__ import annotations


def branchy(a: bool, b: bool, c: bool, d: bool, e: bool, f: bool) -> int:
    total = 0
    if a:
        total += 1
    if b:
        total += 1
    if c:
        total += 1
    if d:
        total += 1
    if e:
        total += 1
    if f:
        total += 1
    if a and b:
        total += 1
    if c and d:
        total += 1
    if e and f:
        total += 1
    if a or c:
        total += 1
    if b or d:
        total += 1
    if e or a:
        total += 1
    return total
""".strip()
        + "\n",
        encoding="utf-8",
    )

    out_dir = tmp_path / "audit-out"
    baseline_path = tmp_path / "baseline.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "cremona.cli",
            "scan",
            "fixture_pkg/hotspot.py",
            "--out-dir",
            str(out_dir),
            "--baseline",
            str(baseline_path),
            "--update-baseline",
        ],
        cwd=fixture_root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "existing baseline when auditing a partial scope" in result.stderr
