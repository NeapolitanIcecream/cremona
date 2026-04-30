from __future__ import annotations

import ast
from pathlib import Path

import cremona.scan as audit
from cremona.core.baseline import build_baseline_diff
from cremona.core.engine import _set_active_profile, run_refactor_audit, run_scan
from cremona.core.models import AuditConfig, HotspotSignal, ScanRequest
from cremona.core.reporting import render_markdown_report
from cremona.core.routing import build_agent_routing_queue
from cremona.profiles import Profile, get_profile
from cremona.python_tools.engine import (
    ScopeLookup,
    collect_python_files,
    parse_ruff_findings,
)


def test_scan_facade_preserves_representative_compatibility_exports() -> None:
    expected_exports = {
        "AuditConfig",
        "HotspotSignal",
        "ScanRequest",
        "load_audit_config",
        "run_scan",
        "run_refactor_audit",
        "render_markdown_report",
        "build_baseline_diff",
        "build_agent_routing_queue",
        "Profile",
        "get_profile",
        "ScopeLookup",
        "parse_ruff_findings",
        "collect_python_files",
        "_set_active_profile",
    }

    assert expected_exports <= set(audit.__all__)
    assert audit.AuditConfig is AuditConfig
    assert audit.HotspotSignal is HotspotSignal
    assert audit.ScanRequest is ScanRequest
    assert audit.run_scan is run_scan
    assert audit.run_refactor_audit is run_refactor_audit
    assert audit.render_markdown_report is render_markdown_report
    assert audit.build_baseline_diff is build_baseline_diff
    assert audit.build_agent_routing_queue is build_agent_routing_queue
    assert audit.Profile is Profile
    assert audit.get_profile is get_profile
    assert audit.ScopeLookup is ScopeLookup
    assert audit.parse_ruff_findings is parse_ruff_findings
    assert audit.collect_python_files is collect_python_files
    assert audit._set_active_profile is _set_active_profile


def test_scan_facade_uses_explicit_exports() -> None:
    scan_path = Path(audit.__file__)
    tree = ast.parse(scan_path.read_text(encoding="utf-8"))

    wildcard_imports = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
        if alias.name == "*"
    ]

    assert wildcard_imports == []
