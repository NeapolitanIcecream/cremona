from __future__ import annotations

import json
from itertools import count
from pathlib import Path
from typing import Any

import pytest

import cremona.scan as audit
from cremona.core import engine as core_engine


def test_run_scan_report_includes_machine_readable_timing_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "example.py").write_text(
        """
from __future__ import annotations


def example() -> int:
    return 1
""".strip()
        + "\n",
        encoding="utf-8",
    )

    original_timing_diagnostics = core_engine._TimingDiagnostics
    clock_ticks = count()

    def fake_clock() -> float:
        return next(clock_ticks) / 1000.0

    def fake_signal_audit(**_: Any) -> list[audit.HotspotSignal]:
        return []

    def fake_dead_code_audit(**_: Any) -> list[dict[str, Any]]:
        return []

    def fake_history_summary(
        *,
        request: audit.RefactorAuditRunRequest,
        scope_state: audit.AuditScopeState,
    ) -> dict[str, Any]:
        return {
            "status": "available",
            "lookback_days": request.lookback_days,
            "max_commit_frequency": 0,
            "max_churn": 0,
            "files": {
                file_name: {
                    "commit_frequency": 0,
                    "churn": 0,
                    "top_coupled_files": [],
                }
                for file_name in scope_state.current_scope_files
            },
        }

    monkeypatch.setattr(
        core_engine,
        "_TimingDiagnostics",
        lambda: original_timing_diagnostics(clock=fake_clock),
    )
    monkeypatch.setattr(core_engine, "_run_ruff_audit", fake_signal_audit)
    monkeypatch.setattr(core_engine, "_run_lizard_audit", fake_signal_audit)
    monkeypatch.setattr(core_engine, "_run_complexipy_audit", fake_signal_audit)
    monkeypatch.setattr(core_engine, "_run_vulture_audit", fake_dead_code_audit)
    monkeypatch.setattr(
        core_engine,
        "_collect_history_summary_for_scope",
        fake_history_summary,
    )

    config = audit.load_audit_config(repo_root=tmp_path)

    report = audit.run_scan(
        audit.ScanRequest(
            scope_targets=["src"],
            out_dir=tmp_path / "audit-out",
            baseline_path=tmp_path / "baseline.json",
            config=config,
            profile="generic-python",
        )
    )

    payload = json.loads(
        (tmp_path / "audit-out" / "report.json").read_text(encoding="utf-8")
    )
    timings = payload["diagnostics"]["timings"]

    assert report["diagnostics"] == payload["diagnostics"]
    assert timings["unit"] == "milliseconds"
    assert set(timings["tools"]) == {"ruff", "lizard", "complexipy", "vulture"}
    assert set(timings["phases"]) == {
        "prepare_scope",
        "audit_tools",
        "aggregate_findings",
        "history_collection",
        "routing_queue",
        "baseline_comparison",
        "repo_verdict",
        "report_assembly",
    }
    assert timings["tools"]["ruff"]["duration_ms"] == 1.0
    assert all(
        isinstance(item["duration_ms"], int | float) and item["duration_ms"] >= 0
        for group in ("phases", "tools")
        for item in timings[group].values()
    )


def test_timing_diagnostics_records_failed_phase_duration() -> None:
    clock_values = iter((10.0, 10.125))
    timings = core_engine._TimingDiagnostics(clock=lambda: next(clock_values))

    with pytest.raises(ValueError, match="boom"):
        with timings.track_phase("history_collection"):
            raise ValueError("boom")

    payload = timings.as_payload()
    assert payload["phases"]["history_collection"]["duration_ms"] == 125.0
