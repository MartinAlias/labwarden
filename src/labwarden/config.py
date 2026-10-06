"""Loads ``labwarden.yaml``.

Secrets never need to live in the YAML: any string may reference environment
variables as ``${NAME}`` or ``${NAME:-default}``. A ``.env`` file next to the
config is loaded first (without overriding variables already set).
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator

DEFAULT_CONFIG_NAME = "labwarden.yaml"
CONFIG_ENV_VAR = "LABWARDEN_CONFIG"

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


class ConfigError(Exception):
    pass


class TargetConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    plugin: str
    enabled: bool = True
    options: dict[str, Any] = Field(default_factory=dict)


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data_dir: Path = Path("data")
    targets: list[TargetConfig] = Field(default_factory=list)

    # Directory of the config file; relative paths resolve against it.
    _base_dir: Path = PrivateAttr(default_factory=Path.cwd)

    @field_validator("targets")
    @classmethod
    def _unique_target_names(cls, targets: list[TargetConfig]) -> list[TargetConfig]:
        names = [t.name for t in targets]
        dupes = sorted({n for n in names if names.count(n) > 1})
        if dupes:
            raise ValueError(f"duplicate target names: {dupes}")
        return targets

    @property
    def base_dir(self) -> Path:
        return self._base_dir

    @property
    def resolved_data_dir(self) -> Path:
        return self.data_dir if self.data_dir.is_absolute() else self._base_dir / self.data_dir

    @property
    def snapshot_db(self) -> Path:
        return self.resolved_data_dir / "snapshots.db"


def find_config(explicit: Path | None = None) -> Path:
    if explicit is not None:
        return explicit
    if env := os.environ.get(CONFIG_ENV_VAR):
        return Path(env)
    return Path.cwd() / DEFAULT_CONFIG_NAME


def load_config(path: Path) -> Config:
    if not path.is_file():
        raise ConfigError(
            f"config file not found: {path}  (copy examples/labwarden.yaml to get started)"
        )
    _load_dotenv(path.parent / ".env")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from exc
    try:
        config = Config.model_validate(_interpolate(raw))
    except ValueError as exc:  # pydantic ValidationError is a ValueError
        raise ConfigError(f"{path}: {exc}") from exc
    config._base_dir = path.resolve().parent
    return config


def _interpolate(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV_REF.sub(_replace_env, value)
    if isinstance(value, list):
        return [_interpolate(v) for v in value]
    if isinstance(value, dict):
        return {k: _interpolate(v) for k, v in value.items()}
    return value


def _replace_env(match: re.Match[str]) -> str:
    name, default = match.group(1), match.group(2)
    if name in os.environ:
        return os.environ[name]
    if default is not None:
        return default
    raise ConfigError(f"environment variable {name} is referenced in the config but not set")


def _load_dotenv(path: Path) -> None:
    """Minimal .env reader: KEY=VALUE lines, # comments, optional quotes."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip().removeprefix("export ").strip()
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        os.environ.setdefault(key, val)
