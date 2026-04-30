from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal, cast

import pytest

import cremona.scan as audit

CONFIG = audit.load_audit_config(repo_root=Path(__file__).resolve().parents[1])
audit._set_active_profile(audit.get_profile("generic-python"))



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
