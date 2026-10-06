from __future__ import annotations

from pathlib import Path

import pytest

from labwarden.collectors.runner import run_collectors
from labwarden.config import ConfigError, load_config


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_loads_and_resolves_relative_paths(lab_dir: Path) -> None:
    config = load_config(lab_dir / "labwarden.yaml")
    assert config.base_dir == lab_dir.resolve()
    assert config.snapshot_db == lab_dir.resolve() / "data" / "snapshots.db"
    assert [t.name for t in config.targets] == ["inventory"]


def test_env_interpolation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LW_TEST_PASSWORD", "s3cret")
    monkeypatch.delenv("LW_TEST_MISSING", raising=False)
    cfg = _write(
        tmp_path / "c.yaml",
        """
targets:
  - name: t
    plugin: manual
    options:
      password: ${LW_TEST_PASSWORD}
      url: ${LW_TEST_MISSING:-http://default}
""",
    )
    options = load_config(cfg).targets[0].options
    assert options == {"password": "s3cret", "url": "http://default"}


def test_missing_env_var_is_an_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LW_TEST_MISSING", raising=False)
    cfg = _write(tmp_path / "c.yaml", "data_dir: ${LW_TEST_MISSING}\n")
    with pytest.raises(ConfigError, match="LW_TEST_MISSING"):
        load_config(cfg)


def test_dotenv_is_loaded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LW_TEST_DOTENV", raising=False)
    _write(tmp_path / ".env", '# comment\nLW_TEST_DOTENV="from-dotenv"\n')
    cfg = _write(tmp_path / "c.yaml", "data_dir: ${LW_TEST_DOTENV}\n")
    assert str(load_config(cfg).data_dir) == "from-dotenv"


@pytest.mark.parametrize(
    "text",
    [
        "unknown_key: 1\n",
        "targets:\n  - {name: a, plugin: manual}\n  - {name: a, plugin: manual}\n",
        "targets: [\n",
    ],
)
def test_invalid_configs(tmp_path: Path, text: str) -> None:
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path / "c.yaml", text))


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.yaml")


def test_runner_collects_and_isolates_failures(lab_dir: Path) -> None:
    _write(
        lab_dir / "labwarden.yaml",
        """
targets:
  - {name: inventory, plugin: manual, options: {file: inventory.yaml}}
  - {name: broken, plugin: manual, options: {file: missing.yaml}}
  - {name: typo, plugin: no-such-plugin}
  - {name: disabled, plugin: no-such-plugin, enabled: false}
""",
    )
    result = run_collectors(load_config(lab_dir / "labwarden.yaml"))

    assert [d.name for d in result.model.devices] == ["router", "nas"]
    assert all(d.source == "inventory" for d in result.model.devices)
    assert set(result.errors) == {"broken", "typo"}
    assert "unknown plugin" in result.errors["typo"]
