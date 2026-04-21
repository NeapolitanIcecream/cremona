from __future__ import annotations

from pathlib import Path

import pytest

import cremona.scan as audit


def _write_pyproject(tmp_path: Path, body: str) -> None:
    (tmp_path / "pyproject.toml").write_text(body.strip() + "\n", encoding="utf-8")


def test_load_audit_config_rejects_signal_with_invalid_kind(tmp_path: Path) -> None:
    _write_pyproject(
        tmp_path,
        """
        [tool.cremona]
        profile = "workflow-app"

        [tool.cremona.profiles.workflow-app]
        base = "generic-python"

        [[tool.cremona.profiles.workflow-app.signals]]
        name = "kwargs_bridge_hits"
        kind = "literal"
        pattern = "legacy"
        points = 2
        """,
    )

    with pytest.raises(ValueError, match="unsupported kind"):
        audit.load_audit_config(repo_root=tmp_path)


def test_load_audit_config_rejects_signal_with_invalid_regex(tmp_path: Path) -> None:
    _write_pyproject(
        tmp_path,
        """
        [tool.cremona]
        profile = "workflow-app"

        [tool.cremona.profiles.workflow-app]
        base = "generic-python"

        [[tool.cremona.profiles.workflow-app.signals]]
        name = "kwargs_bridge_hits"
        kind = "regex_count"
        pattern = "["
        points_per = 10
        max_points = 6
        """,
    )

    with pytest.raises(ValueError, match="invalid regex pattern"):
        audit.load_audit_config(repo_root=tmp_path)


@pytest.mark.parametrize(
    ("signal_block", "message"),
    [
        (
            """
            name = "request_wrapper"
            kind = "regex_flag"
            pattern = "request"
            points = 0
            """,
            "positive points value",
        ),
        (
            """
            name = "kwargs_bridge_hits"
            kind = "regex_count"
            pattern = "legacy"
            points_per = 0
            max_points = 6
            """,
            "positive points_per",
        ),
    ],
)
def test_load_audit_config_rejects_non_positive_signal_scores(
    tmp_path: Path,
    signal_block: str,
    message: str,
) -> None:
    _write_pyproject(
        tmp_path,
        f"""
        [tool.cremona]
        profile = "workflow-app"

        [tool.cremona.profiles.workflow-app]
        base = "generic-python"

        [[tool.cremona.profiles.workflow-app.signals]]
        {signal_block}
        """,
    )

    with pytest.raises(ValueError, match=message):
        audit.load_audit_config(repo_root=tmp_path)


def test_load_audit_config_rejects_bonus_with_invalid_operator(tmp_path: Path) -> None:
    _write_pyproject(
        tmp_path,
        """
        [tool.cremona]
        profile = "workflow-app"

        [tool.cremona.profiles.workflow-app]
        base = "generic-python"

        [[tool.cremona.profiles.workflow-app.signals]]
        name = "kwargs_bridge_hits"
        kind = "regex_count"
        pattern = "legacy"
        points_per = 10
        max_points = 6

        [[tool.cremona.profiles.workflow-app.routing_bonuses]]
        name = "migration_pressure"
        points = 4
        all = [
          { source = "signal", name = "kwargs_bridge_hits", op = "contains", value = 1 },
        ]
        """,
    )

    with pytest.raises(ValueError, match="unsupported operator"):
        audit.load_audit_config(repo_root=tmp_path)
