from __future__ import annotations

import json
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import cremona.scan as audit
from cremona.core import engine as core_engine

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
