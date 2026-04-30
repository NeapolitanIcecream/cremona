from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path



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
