from __future__ import annotations

import pytest

from cremona import cli


def test_main_dispatches_scan_command_arguments_in_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forwarded_args: list[list[str] | None] = []

    def fake_scan_main(argv: list[str] | None = None) -> int:
        forwarded_args.append(argv)
        return 7

    monkeypatch.setattr(cli.scan_module, "main", fake_scan_main)

    exit_code = cli.main(["scan", "src", "--profile", "generic-python"])

    assert exit_code == 7
    assert forwarded_args == [["src", "--profile", "generic-python"]]


def test_main_without_command_prints_help_and_returns_nonzero(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = cli.main([])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "usage: cremona" in captured.out
    assert "{scan}" in captured.out
    assert captured.err == ""


def test_main_rejects_unknown_commands_before_scan_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_called = False

    def fake_scan_main(argv: list[str] | None = None) -> int:
        nonlocal scan_called
        scan_called = True
        return 0

    monkeypatch.setattr(cli.scan_module, "main", fake_scan_main)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["unknown"])

    assert exc_info.value.code == 2
    assert scan_called is False
