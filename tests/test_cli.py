from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from labwarden.cli import app

runner = CliRunner()


def _run(lab_dir: Path, *args: str):
    return runner.invoke(app, [*args, "--config", str(lab_dir / "labwarden.yaml")])


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "labwarden" in result.output


def test_plugins_lists_manual() -> None:
    result = runner.invoke(app, ["plugins"])
    assert result.exit_code == 0
    assert "manual" in result.output


def test_check(lab_dir: Path) -> None:
    result = _run(lab_dir, "check")
    assert result.exit_code == 0, result.output
    assert "ok" in result.output


def test_collect_show_and_diff(lab_dir: Path) -> None:
    assert _run(lab_dir, "diff").exit_code == 1  # no snapshots yet

    result = _run(lab_dir, "collect", "--label", "first")
    assert result.exit_code == 0, result.output
    assert "#1" in result.output

    inventory = lab_dir / "inventory.yaml"
    inventory.write_text(
        inventory.read_text(encoding="utf-8").replace("192.168.1.20", "192.168.1.21"),
        encoding="utf-8",
    )
    assert _run(lab_dir, "collect").exit_code == 0

    result = _run(lab_dir, "diff")
    assert result.exit_code == 0, result.output
    assert "devices[nas]" in result.output
    assert "192.168.1.21" in result.output

    result = _run(lab_dir, "show")
    assert result.exit_code == 0
    assert "nas" in result.output

    result = _run(lab_dir, "show", "--kind", "subnets")
    assert result.exit_code == 0
    assert "192.168.1.0/24" in result.output

    result = _run(lab_dir, "snapshots")
    assert result.exit_code == 0
    assert "first" in result.output


def test_missing_config_exits_cleanly(tmp_path: Path) -> None:
    result = runner.invoke(app, ["check", "--config", str(tmp_path / "nope.yaml")])
    assert result.exit_code == 2
