from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import cremona.scan as audit

CONFIG = audit.load_audit_config(repo_root=Path(__file__).resolve().parents[1])
audit._set_active_profile(audit.get_profile("generic-python"))



@contextmanager
def _use_profile(profile: audit.Profile):
    previous = audit._set_active_profile(profile)
    try:
        yield
    finally:
        audit._set_active_profile(previous)



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
