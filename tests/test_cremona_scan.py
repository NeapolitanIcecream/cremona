from __future__ import annotations

import json
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Literal

import cremona.scan as audit
from cremona.core import engine as core_engine

CONFIG = audit.load_audit_config(repo_root=Path(__file__).resolve().parents[1])
audit._set_active_profile(audit.get_profile("recoleta"))


@contextmanager
def _use_profile(name: str):
    previous = audit._set_active_profile(audit.get_profile(name))
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
    file: str = "recoleta/example.py",
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
            "recoleta/branchy.py": {
                "summary": {
                    "covered_branches": 6,
                    "num_branches": 8,
                    "covered_lines": 10,
                    "num_statements": 12,
                }
            },
            "recoleta/line_only.py": {
                "summary": {
                    "covered_lines": 9,
                    "num_statements": 12,
                }
            },
            "recoleta/unknown.py": {"summary": {}},
        },
    }


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
        '151,31,1241,7,154,"branchy@42-196@pkg/mod.py","pkg/mod.py",'
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
    assert finding.metrics["nloc"] == 151
    assert finding.metrics["parameter_count"] == 7


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
    hotspots = audit.aggregate_hotspots(findings)
    assert len(hotspots) == 2


def test_aggregate_hotspots_marks_single_warning_as_monitor() -> None:
    hotspots = audit.aggregate_hotspots(
        [
            _signal(
                tool="ruff",
                severity="warning",
                metrics={"complexity": 12},
            )
        ]
    )

    assert len(hotspots) == 1
    assert hotspots[0]["classification"] == "monitor"


def test_aggregate_hotspots_marks_two_warning_tools_as_refactor_soon() -> None:
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
        ]
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
        ]
    )

    assert hotspots[0]["classification"] == "refactor_now"


def test_aggregate_hotspots_marks_critical_ruff_as_refactor_soon() -> None:
    hotspots = audit.aggregate_hotspots(
        [
            _signal(
                tool="ruff",
                severity="critical",
                metrics={"complexity": 26},
            )
        ]
    )

    assert hotspots[0]["classification"] == "refactor_soon"


def test_build_history_summary_reads_commit_frequency_churn_and_coupling() -> None:
    raw_text = "\n".join(
        [
            "commit a1",
            "4\t1\trecoleta/cli/app.py",
            "1\t0\trecoleta/pipeline/service.py",
            "commit b2",
            "2\t2\trecoleta/cli/app.py",
            "3\t1\trecoleta/pipeline/service.py",
            "1\t0\trecoleta/translation.py",
            "commit c3",
            "5\t0\trecoleta/translation.py",
            "",
        ]
    )

    summary = audit.build_history_summary(
        raw_text=raw_text,
        tracked_files={
            "recoleta/cli/app.py",
            "recoleta/pipeline/service.py",
            "recoleta/translation.py",
        },
        current_scope_files=[
            "recoleta/cli/app.py",
            "recoleta/pipeline/service.py",
        ],
        min_shared_commits=2,
        coupling_ignore_commit_file_count=10,
        lookback_days=180,
    )

    assert summary["status"] == "available"
    assert summary["max_commit_frequency"] == 2
    assert summary["max_churn"] == 9
    cli_history = summary["files"]["recoleta/cli/app.py"]
    assert cli_history["commit_frequency"] == 2
    assert cli_history["churn"] == 9
    assert cli_history["top_coupled_files"] == [
        {
            "file": "recoleta/pipeline/service.py",
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
        targets=["recoleta"],
        tracked_files={"recoleta/example.py"},
        current_scope_files=["recoleta/example.py"],
        lookback_days=180,
        min_shared_commits=3,
        coupling_ignore_commit_file_count=25,
    )

    assert summary["status"] == "unavailable"
    assert summary["files"]["recoleta/example.py"]["commit_frequency"] == 0
    assert summary["files"]["recoleta/example.py"]["top_coupled_files"] == []


def test_build_history_summary_ignores_sweep_commit_for_coupling() -> None:
    raw_text = "\n".join(
        [
            "commit a1",
            "1\t0\trecoleta/a.py",
            "1\t0\trecoleta/b.py",
            "1\t0\trecoleta/c.py",
            "commit b2",
            "1\t0\trecoleta/a.py",
            "1\t0\trecoleta/b.py",
            "",
        ]
    )

    summary = audit.build_history_summary(
        raw_text=raw_text,
        tracked_files={
            "recoleta/a.py",
            "recoleta/b.py",
            "recoleta/c.py",
        },
        current_scope_files=[
            "recoleta/a.py",
            "recoleta/b.py",
            "recoleta/c.py",
        ],
        min_shared_commits=1,
        coupling_ignore_commit_file_count=2,
        lookback_days=180,
    )

    assert summary["files"]["recoleta/a.py"]["commit_frequency"] == 2
    assert summary["files"]["recoleta/a.py"]["top_coupled_files"] == [
        {
            "file": "recoleta/b.py",
            "shared_commits": 1,
            "in_scope": True,
        }
    ]


def test_history_collection_inputs_include_explicit_scope_files_outside_default_targets(
    tmp_path: Path,
) -> None:
    lookup = _lookup_for(tmp_path, "main.py")
    scope_state = audit.AuditScopeState(
        files=[tmp_path / "main.py"],
        current_scope_files=["main.py"],
        default_scope_files=("recoleta/example.py",),
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
    assert tracked_files == ("main.py", "recoleta/example.py")


def test_load_coverage_summary_prefers_branch_then_line_then_unknown(tmp_path: Path) -> None:
    coverage_path = tmp_path / "coverage.json"
    coverage_path.write_text(json.dumps(_coverage_payload()), encoding="utf-8")

    coverage = audit.load_coverage_summary(
        coverage_json=coverage_path,
        repo_root=tmp_path,
        tracked_files={
            "recoleta/branchy.py",
            "recoleta/line_only.py",
            "recoleta/unknown.py",
            "recoleta/missing.py",
        },
    )

    assert coverage["status"] == "available"
    assert coverage["files"]["recoleta/branchy.py"] == {
        "mode": "branch",
        "fraction": 0.75,
    }
    assert coverage["files"]["recoleta/line_only.py"] == {
        "mode": "line",
        "fraction": 0.75,
    }
    assert coverage["files"]["recoleta/unknown.py"] == {
        "mode": "unknown",
        "fraction": None,
    }
    assert coverage["files"]["recoleta/missing.py"] == {
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


def test_build_agent_ambiguity_index_detects_shims_facades_and_legacy(tmp_path: Path) -> None:
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

    index = audit.build_agent_ambiguity_index(
        repo_root=tmp_path,
        files=[shadow_module, facade_path, compat_path],
    )

    assert index["pkg/cli.py"]["module_package_shadow"] == 1
    assert index["pkg/cli.py"]["wildcard_reexport"] == 1
    assert index["pkg/storage.py"]["facade_reexport"] == 1
    assert index["pkg/translate.py"]["legacy_keyword_hits"] >= 2
    assert index["pkg/translate.py"]["compat_request_wrapper"] == 1


def test_generic_python_profile_keeps_recoleta_rules_out_of_core() -> None:
    with _use_profile("generic-python"):
        assert audit.infer_subsystem("recoleta/cli.py") == "recoleta"


def test_recoleta_profile_preserves_recoleta_specific_subsystem_mapping() -> None:
    with _use_profile("recoleta"):
        assert audit.infer_subsystem("recoleta/cli.py") == "cli"


def test_generic_python_profile_scans_non_recoleta_fixture_end_to_end(
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


def test_build_agent_routing_queue_prioritizes_high_churn_ambiguous_file() -> None:
    queue = audit.build_agent_routing_queue(
        scope_files=["recoleta/cli.py", "recoleta/example.py"],
        hotspots=[
            {
                "id": "recoleta/example.py::branchy",
                "file": "recoleta/example.py",
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
                "id": "recoleta/cli.py::function::legacy_entrypoint",
                "file": "recoleta/cli.py",
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
                "recoleta/cli.py": {
                    "commit_frequency": 10,
                    "churn": 500,
                    "top_coupled_files": [
                        {
                            "file": "recoleta/cli/app.py",
                            "shared_commits": 4,
                            "in_scope": False,
                        }
                    ],
                },
                "recoleta/example.py": {
                    "commit_frequency": 1,
                    "churn": 10,
                    "top_coupled_files": [],
                },
            },
        },
        coverage_summary={
            "status": "available",
            "files": {
                "recoleta/cli.py": {"mode": "unknown", "fraction": None},
                "recoleta/example.py": {"mode": "branch", "fraction": 0.9},
            },
        },
        ambiguity_index={
            "recoleta/cli.py": {
                "module_package_shadow": 1,
                "wildcard_reexport": 1,
                "facade_reexport": 0,
                "legacy_keyword_hits": 6,
                "compat_request_wrapper": 0,
            },
            "recoleta/example.py": {
                "module_package_shadow": 0,
                "wildcard_reexport": 0,
                "facade_reexport": 0,
                "legacy_keyword_hits": 0,
                "compat_request_wrapper": 0,
            },
        },
    )

    assert queue[0]["file"] == "recoleta/cli.py"
    assert queue[0]["priority_band"] in {"investigate_now", "investigate_soon"}
    assert queue[0]["dead_code_candidate_count"] == 1
    assert queue[1]["file"] == "recoleta/example.py"
    assert queue[1]["hotspot_summary"]["monitor"] == 1


def test_build_agent_routing_queue_elevates_compatibility_heavy_file() -> None:
    queue = audit.build_agent_routing_queue(
        scope_files=["recoleta/translation.py", "recoleta/example.py"],
        hotspots=[],
        dead_code_candidates=[],
        history_summary={
            "status": "available",
            "max_commit_frequency": 20,
            "max_churn": 1000,
            "files": {
                "recoleta/translation.py": {
                    "commit_frequency": 18,
                    "churn": 600,
                    "top_coupled_files": [
                        {
                            "file": "recoleta/cli/app.py",
                            "shared_commits": 7,
                            "in_scope": False,
                        },
                        {
                            "file": "recoleta/cli/translate.py",
                            "shared_commits": 7,
                            "in_scope": False,
                        },
                        {
                            "file": "recoleta/materialize.py",
                            "shared_commits": 7,
                            "in_scope": False,
                        },
                        {
                            "file": "recoleta/trends.py",
                            "shared_commits": 7,
                            "in_scope": False,
                        },
                        {
                            "file": "recoleta/pipeline/trends_stage.py",
                            "shared_commits": 6,
                            "in_scope": False,
                        },
                    ],
                },
                "recoleta/example.py": {
                    "commit_frequency": 1,
                    "churn": 10,
                    "top_coupled_files": [],
                },
            },
        },
        coverage_summary={
            "status": "unavailable",
            "files": {
                "recoleta/translation.py": {"mode": "unknown", "fraction": None},
                "recoleta/example.py": {"mode": "unknown", "fraction": None},
            },
        },
        ambiguity_index={
            "recoleta/translation.py": {
                "module_package_shadow": 0,
                "wildcard_reexport": 0,
                "facade_reexport": 0,
                "legacy_keyword_hits": 80,
                "compat_request_wrapper": 1,
            },
            "recoleta/example.py": {
                "module_package_shadow": 0,
                "wildcard_reexport": 0,
                "facade_reexport": 0,
                "legacy_keyword_hits": 0,
                "compat_request_wrapper": 0,
            },
        },
    )

    assert queue[0]["file"] == "recoleta/translation.py"
    assert queue[0]["priority_band"] == "investigate_soon"
    assert queue[0]["priority_components"]["compatibility_pressure_score"] > 0


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


def test_build_baseline_diff_marks_new_hotspots() -> None:
    current_hotspots = [
        {
            "id": "recoleta/example.py::branchy",
            "file": "recoleta/example.py",
            "symbol": "branchy",
            "classification": "refactor_soon",
            "tools": ["ruff"],
            "metrics": {"ruff": {"complexity": 16}},
        }
    ]

    diff = audit.build_baseline_diff(
        current_hotspots=current_hotspots,
        current_dead_code_candidates=[],
        baseline_report={"hotspots": [], "dead_code_candidates": []},
        scope_files=["recoleta/example.py"],
        config=CONFIG,
    )

    assert diff["new"][0]["kind"] == "hotspot"
    assert diff["new"][0]["symbol"] == "branchy"


def test_build_baseline_diff_marks_worsened_hotspots() -> None:
    baseline_report = {
        "hotspots": [
            {
                "id": "recoleta/example.py::branchy",
                "file": "recoleta/example.py",
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
            "id": "recoleta/example.py::branchy",
            "file": "recoleta/example.py",
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
        scope_files=["recoleta/example.py"],
        config=CONFIG,
    )

    assert diff["worsened"][0]["kind"] == "hotspot"
    assert "classification" in diff["worsened"][0]["reasons"]


def test_build_baseline_diff_ignores_same_band_lizard_nloc_growth() -> None:
    baseline_report = {
        "hotspots": [
            {
                "id": "recoleta/example.py::branchy",
                "file": "recoleta/example.py",
                "symbol": "branchy",
                "classification": "monitor",
                "tools": ["lizard"],
                "metrics": {"lizard": {"ccn": 10, "nloc": 97, "parameter_count": 4}},
            }
        ],
        "dead_code_candidates": [],
    }
    current_hotspots = [
        {
            "id": "recoleta/example.py::branchy",
            "file": "recoleta/example.py",
            "symbol": "branchy",
            "classification": "monitor",
            "tools": ["lizard"],
            "metrics": {"lizard": {"ccn": 10, "nloc": 105, "parameter_count": 4}},
        }
    ]

    diff = audit.build_baseline_diff(
        current_hotspots=current_hotspots,
        current_dead_code_candidates=[],
        baseline_report=baseline_report,
        scope_files=["recoleta/example.py"],
        config=CONFIG,
    )

    assert diff["has_regressions"] is False
    assert diff["worsened"] == []


def test_build_baseline_diff_ignores_new_monitor_lizard_nloc_hotspot() -> None:
    current_hotspots = [
        {
            "id": "recoleta/example.py::wrapped",
            "file": "recoleta/example.py",
            "symbol": "wrapped",
            "classification": "monitor",
            "tools": ["lizard"],
            "metrics": {"lizard": {"ccn": 8, "nloc": 82, "parameter_count": 3}},
        }
    ]

    diff = audit.build_baseline_diff(
        current_hotspots=current_hotspots,
        current_dead_code_candidates=[],
        baseline_report={"hotspots": [], "dead_code_candidates": []},
        scope_files=["recoleta/example.py"],
        config=CONFIG,
    )

    assert diff["has_regressions"] is False
    assert diff["new"] == []


def test_build_baseline_diff_marks_resolved_hotspots() -> None:
    baseline_report = {
        "hotspots": [
            {
                "id": "recoleta/example.py::branchy",
                "file": "recoleta/example.py",
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
        scope_files=["recoleta/example.py"],
        config=CONFIG,
    )

    assert diff["resolved"][0]["kind"] == "hotspot"
    assert diff["resolved"][0]["symbol"] == "branchy"


def test_render_markdown_report_contains_required_sections() -> None:
    report = {
        "summary": {
            "files_scanned": 1,
            "hotspots_total": 1,
            "monitor_total": 0,
            "refactor_soon_total": 1,
            "refactor_now_total": 0,
            "agent_routing_queue_total": 1,
            "investigate_now_total": 0,
            "investigate_soon_total": 1,
            "watch_total": 0,
            "dead_code_candidates_total": 1,
            "dead_code_high_confidence_total": 1,
        },
        "repo_verdict": {
            "status": "strained",
            "debt_status": "strained",
            "routing_pressure": "investigate_soon",
            "summary": "Existing structural debt remains, but the current scope did not regress. Routing pressure is investigate_soon. Signal health is partial: missing coverage.",
            "signal_health": "partial",
            "missing_signals": ["coverage"],
        },
        "history_summary": {"status": "available", "lookback_days": 180},
        "tool_summaries": {
            "ruff": {"findings_total": 1, "warning": 1, "high": 0, "critical": 0},
            "lizard": {"findings_total": 1, "warning": 1, "high": 0, "critical": 0},
            "complexipy": {
                "findings_total": 0,
                "warning": 0,
                "high": 0,
                "critical": 0,
            },
            "vulture": {
                "findings_total": 1,
                "review_candidate": 0,
                "high_confidence_candidate": 1,
            },
        },
        "hotspots": [
            {
                "classification": "refactor_soon",
                "tool_count": 2,
                "file": "recoleta/example.py",
                "symbol": "branchy",
                "tools": ["lizard", "ruff"],
                "metrics": {
                    "lizard": {"ccn": 18, "nloc": 90, "parameter_count": 4},
                    "ruff": {"complexity": 16},
                },
            }
        ],
        "dead_code_candidates": [
            {
                "classification": "high_confidence_candidate",
                "confidence": 90,
                "file": "recoleta/example.py",
                "symbol": "unused_helper",
                "kind": "function",
            }
        ],
        "agent_routing_queue": [
            {
                "file": "recoleta/example.py",
                "priority_band": "investigate_soon",
                "priority_score": 40,
                "change_frequency": 4,
                "churn": 20,
                "top_coupled_files": [],
                "coverage": {"mode": "branch", "fraction": 0.8},
            }
        ],
        "baseline_diff": {
            "baseline_available": True,
            "has_regressions": False,
            "new": [],
            "worsened": [],
            "resolved": [],
        },
        "recommended_refactor_queue": [
            {
                "subsystem": "pipeline",
                "investigate_now": 0,
                "investigate_soon": 0,
                "watch": 0,
            },
            {
                "subsystem": "other",
                "investigate_now": 0,
                "investigate_soon": 1,
                "watch": 0,
            },
        ],
    }

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
    report = {
        "summary": {
            "files_scanned": 1,
            "hotspots_total": 1,
            "monitor_total": 0,
            "refactor_soon_total": 1,
            "refactor_now_total": 0,
            "agent_routing_queue_total": 0,
            "investigate_now_total": 0,
            "investigate_soon_total": 0,
            "watch_total": 0,
            "dead_code_candidates_total": 0,
            "dead_code_high_confidence_total": 0,
        },
        "repo_verdict": {
            "status": "corroding",
            "debt_status": "corroding",
            "routing_pressure": "none",
            "summary": "Structural debt is regressing in the current scope.",
            "has_regressions": True,
            "signal_health": "full",
            "missing_signals": [],
            "refactor_now_total": 0,
            "investigate_now_total": 0,
            "investigate_soon_total": 0,
        },
        "hotspots": [
            {
                "id": "recoleta/example.py::branchy",
                "file": "recoleta/example.py",
                "symbol": "branchy",
                "classification": "refactor_soon",
                "tools": ["ruff"],
                "metrics": {"ruff": {"complexity": 16}},
            }
        ],
        "dead_code_candidates": [],
        "agent_routing_queue": [],
        "history_summary": {
            "status": "available",
            "lookback_days": 180,
            "max_commit_frequency": 0,
            "max_churn": 0,
            "files": {},
        },
        "tool_summaries": {},
        "baseline_diff": {
            "baseline_available": True,
            "baseline_path": "quality/refactor-baseline.json",
            "has_regressions": True,
            "new": [{"kind": "hotspot"}],
            "worsened": [],
            "resolved": [],
        },
        "recommended_refactor_queue": [],
        "scope": {"files": ["recoleta/example.py"]},
        "schema_version": 2,
        "generated_at": "2026-04-02T00:00:00+00:00",
    }

    snapshot = audit.build_baseline_snapshot(report)

    assert snapshot["baseline_diff"]["baseline_available"] is False
    assert snapshot["baseline_diff"]["has_regressions"] is False
    assert snapshot["baseline_diff"]["new"] == []
    assert snapshot["history_summary"]["status"] == "available"
    assert snapshot["agent_routing_queue"] == []
    assert snapshot["repo_verdict"]["status"] == "strained"


def test_build_baseline_snapshot_merges_partial_scope_updates() -> None:
    baseline_report = {
        "scope": {
            "files": ["recoleta/in_scope.py", "recoleta/out_of_scope.py"],
            "file_count": 2,
        },
        "hotspots": [
            {
                "id": "recoleta/in_scope.py::branchy",
                "file": "recoleta/in_scope.py",
                "symbol": "branchy",
                "classification": "monitor",
                "subsystem": "other",
                "tools": ["ruff"],
                "metrics": {"ruff": {"complexity": 12}},
                "signals": [
                    {
                        "tool": "ruff",
                        "severity": "warning",
                        "symbol": "branchy",
                        "line": 10,
                        "metrics": {"complexity": 12},
                        "message": "complexity=12",
                    }
                ],
            },
            {
                "id": "recoleta/out_of_scope.py::other_hotspot",
                "file": "recoleta/out_of_scope.py",
                "symbol": "other_hotspot",
                "classification": "refactor_now",
                "subsystem": "other",
                "tools": ["complexipy"],
                "metrics": {"complexipy": {"complexity": 55}},
                "signals": [
                    {
                        "tool": "complexipy",
                        "severity": "critical",
                        "symbol": "other_hotspot",
                        "line": 20,
                        "metrics": {"complexity": 55},
                        "message": "complexity=55",
                    }
                ],
            },
        ],
        "dead_code_candidates": [
            {
                "id": "recoleta/out_of_scope.py::function::unused_helper",
                "file": "recoleta/out_of_scope.py",
                "line": 30,
                "symbol": "unused_helper",
                "kind": "function",
                "confidence": 90,
                "classification": "high_confidence_candidate",
                "subsystem": "other",
                "size": None,
            }
        ],
        "agent_routing_queue": [
            {
                "file": "recoleta/out_of_scope.py",
                "subsystem": "other",
                "priority_score": 80,
                "priority_band": "investigate_now",
                "change_frequency": 8,
                "churn": 100,
                "top_coupled_files": [],
                "hotspot_summary": {
                    "refactor_now": 1,
                    "refactor_soon": 0,
                    "monitor": 0,
                    "multi_tool_monitor": 0,
                    "top_symbols": [],
                },
                "ambiguity_signals": {
                    "module_package_shadow": 0,
                    "wildcard_reexport": 0,
                    "facade_reexport": 0,
                    "legacy_keyword_hits": 0,
                    "compat_request_wrapper": 0,
                },
                "dead_code_candidate_count": 1,
                "coverage": {"mode": "unknown", "fraction": None},
                "priority_components": {
                    "change_score": 10,
                    "coupling_score": 0,
                    "static_score": 5,
                    "ambiguity_score": 0,
                    "dead_code_score": 3,
                    "coverage_risk_score": 0,
                },
            }
        ],
        "history_summary": {
            "status": "available",
            "lookback_days": 180,
            "max_commit_frequency": 8,
            "max_churn": 100,
            "files": {
                "recoleta/out_of_scope.py": {
                    "commit_frequency": 8,
                    "churn": 100,
                    "top_coupled_files": [],
                }
            },
        },
    }
    report = {
        "summary": {
            "files_scanned": 1,
            "hotspots_total": 1,
            "monitor_total": 0,
            "refactor_soon_total": 1,
            "refactor_now_total": 0,
            "agent_routing_queue_total": 1,
            "investigate_now_total": 0,
            "investigate_soon_total": 1,
            "watch_total": 0,
            "dead_code_candidates_total": 0,
            "dead_code_high_confidence_total": 0,
        },
        "repo_verdict": {
            "status": "strained",
            "debt_status": "strained",
            "routing_pressure": "investigate_soon",
            "summary": "Existing structural debt remains, but the current scope did not regress. Routing pressure is investigate_soon. Signal health is partial: missing coverage.",
            "has_regressions": False,
            "signal_health": "partial",
            "missing_signals": ["coverage"],
            "refactor_now_total": 0,
            "investigate_now_total": 0,
            "investigate_soon_total": 1,
        },
        "hotspots": [
            {
                "id": "recoleta/in_scope.py::branchy",
                "file": "recoleta/in_scope.py",
                "symbol": "branchy",
                "classification": "refactor_soon",
                "subsystem": "other",
                "tools": ["ruff"],
                "metrics": {"ruff": {"complexity": 26}},
                "signals": [
                    {
                        "tool": "ruff",
                        "severity": "critical",
                        "symbol": "branchy",
                        "line": 10,
                        "metrics": {"complexity": 26},
                        "message": "complexity=26",
                    }
                ],
            }
        ],
        "dead_code_candidates": [],
        "tool_summaries": {
            "ruff": {"findings_total": 1, "warning": 0, "high": 0, "critical": 1},
            "lizard": {"findings_total": 0, "warning": 0, "high": 0, "critical": 0},
            "complexipy": {
                "findings_total": 0,
                "warning": 0,
                "high": 0,
                "critical": 0,
            },
            "vulture": {
                "findings_total": 0,
                "review_candidate": 0,
                "high_confidence_candidate": 0,
            },
        },
        "baseline_diff": {
            "baseline_available": True,
            "baseline_path": "quality/refactor-baseline.json",
            "has_regressions": True,
            "new": [{"kind": "hotspot"}],
            "worsened": [],
            "resolved": [],
        },
        "agent_routing_queue": [
            {
                "file": "recoleta/in_scope.py",
                "subsystem": "other",
                "priority_score": 50,
                "priority_band": "investigate_soon",
                "change_frequency": 5,
                "churn": 40,
                "top_coupled_files": [],
                "hotspot_summary": {
                    "refactor_now": 0,
                    "refactor_soon": 1,
                    "monitor": 0,
                    "multi_tool_monitor": 0,
                    "top_symbols": [],
                },
                "ambiguity_signals": {
                    "module_package_shadow": 0,
                    "wildcard_reexport": 0,
                    "facade_reexport": 0,
                    "legacy_keyword_hits": 0,
                    "compat_request_wrapper": 0,
                },
                "dead_code_candidate_count": 0,
                "coverage": {"mode": "line", "fraction": 0.5},
                "priority_components": {
                    "change_score": 10,
                    "coupling_score": 0,
                    "static_score": 3,
                    "ambiguity_score": 0,
                    "dead_code_score": 0,
                    "coverage_risk_score": 5,
                },
            }
        ],
        "history_summary": {
            "status": "available",
            "lookback_days": 180,
            "max_commit_frequency": 5,
            "max_churn": 40,
            "files": {
                "recoleta/in_scope.py": {
                    "commit_frequency": 5,
                    "churn": 40,
                    "top_coupled_files": [],
                }
            },
        },
        "recommended_refactor_queue": [],
        "scope": {"files": ["recoleta/in_scope.py"], "file_count": 1},
        "schema_version": 2,
        "generated_at": "2026-04-02T00:00:00+00:00",
    }

    snapshot = audit.build_baseline_snapshot(
        report,
        baseline_report=baseline_report,
        scope_files=["recoleta/in_scope.py"],
    )

    assert [item["id"] for item in snapshot["hotspots"]] == [
        "recoleta/out_of_scope.py::other_hotspot",
        "recoleta/in_scope.py::branchy",
    ]
    assert snapshot["summary"]["files_scanned"] == 2
    assert snapshot["summary"]["hotspots_total"] == 2
    assert snapshot["tool_summaries"]["ruff"]["critical"] == 1
    assert snapshot["tool_summaries"]["complexipy"]["critical"] == 1
    assert snapshot["dead_code_candidates"][0]["file"] == "recoleta/out_of_scope.py"
    assert [item["file"] for item in snapshot["agent_routing_queue"]] == [
        "recoleta/out_of_scope.py",
        "recoleta/in_scope.py",
    ]
    assert snapshot["history_summary"]["files"]["recoleta/out_of_scope.py"]["churn"] == 100
    assert snapshot["baseline_diff"]["has_regressions"] is False


def test_build_baseline_snapshot_accepts_v1_baseline_without_routing_fields() -> None:
    baseline_report = {
        "scope": {
            "files": ["recoleta/in_scope.py", "recoleta/out_of_scope.py"],
            "file_count": 2,
        },
        "hotspots": [],
        "dead_code_candidates": [],
    }
    report = {
        "summary": {
            "files_scanned": 1,
            "hotspots_total": 0,
            "monitor_total": 0,
            "refactor_soon_total": 0,
            "refactor_now_total": 0,
            "agent_routing_queue_total": 1,
            "investigate_now_total": 0,
            "investigate_soon_total": 0,
            "watch_total": 1,
            "dead_code_candidates_total": 0,
            "dead_code_high_confidence_total": 0,
        },
        "repo_verdict": {
            "status": "stable",
            "debt_status": "stable",
            "routing_pressure": "watch_only",
            "summary": "No structural debt regressions were detected in the current scope.",
            "has_regressions": False,
            "refactor_now_total": 0,
            "investigate_now_total": 0,
            "investigate_soon_total": 0,
        },
        "hotspots": [],
        "dead_code_candidates": [],
        "tool_summaries": {
            "ruff": {"findings_total": 0, "warning": 0, "high": 0, "critical": 0},
            "lizard": {"findings_total": 0, "warning": 0, "high": 0, "critical": 0},
            "complexipy": {
                "findings_total": 0,
                "warning": 0,
                "high": 0,
                "critical": 0,
            },
            "vulture": {
                "findings_total": 0,
                "review_candidate": 0,
                "high_confidence_candidate": 0,
            },
        },
        "agent_routing_queue": [
            {
                "file": "recoleta/in_scope.py",
                "subsystem": "other",
                "priority_score": 20,
                "priority_band": "watch",
                "change_frequency": 1,
                "churn": 2,
                "top_coupled_files": [],
                "hotspot_summary": {
                    "refactor_now": 0,
                    "refactor_soon": 0,
                    "monitor": 0,
                    "multi_tool_monitor": 0,
                    "top_symbols": [],
                },
                "ambiguity_signals": {
                    "module_package_shadow": 0,
                    "wildcard_reexport": 0,
                    "facade_reexport": 0,
                    "legacy_keyword_hits": 0,
                    "compat_request_wrapper": 0,
                },
                "dead_code_candidate_count": 0,
                "coverage": {"mode": "unknown", "fraction": None},
                "priority_components": {
                    "change_score": 2,
                    "coupling_score": 0,
                    "static_score": 0,
                    "ambiguity_score": 0,
                    "dead_code_score": 0,
                    "coverage_risk_score": 0,
                },
            }
        ],
        "history_summary": {
            "status": "available",
            "lookback_days": 180,
            "max_commit_frequency": 1,
            "max_churn": 2,
            "files": {
                "recoleta/in_scope.py": {
                    "commit_frequency": 1,
                    "churn": 2,
                    "top_coupled_files": [],
                }
            },
        },
        "baseline_diff": {
            "baseline_available": True,
            "baseline_path": "quality/refactor-baseline.json",
            "has_regressions": False,
            "new": [],
            "worsened": [],
            "resolved": [],
        },
        "recommended_refactor_queue": [],
        "scope": {"files": ["recoleta/in_scope.py"], "file_count": 1},
        "schema_version": 2,
        "generated_at": "2026-04-02T00:00:00+00:00",
    }

    snapshot = audit.build_baseline_snapshot(
        report,
        baseline_report=baseline_report,
        scope_files=["recoleta/in_scope.py"],
    )

    assert snapshot["agent_routing_queue"][0]["file"] == "recoleta/in_scope.py"
    assert snapshot["history_summary"]["files"]["recoleta/in_scope.py"]["commit_frequency"] == 1
    assert snapshot["summary"]["agent_routing_queue_total"] == 1


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
    assert payload["schema_version"] == 2
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
    assert payload["dead_code_candidates"]


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
