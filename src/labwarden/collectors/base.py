"""Base class for read-only collector plugins.

A collector reads one source (a host over SSH, the Docker API, a Pi-hole, ...)
and translates what it sees into a LabModel. Collectors must never change the
systems they read. This module enforces that at the code layer:

* A subclass may only define public methods whose names start with a read-only
  verb (see ``READ_ONLY_PREFIXES``). A method called ``set_rule`` or
  ``restart_container`` fails at class-definition time, before it can ever run.
* A collector must declare which LabModel collections it ``provides``. The
  runner rejects output outside that manifest, so the agent can trust each
  collector's declared coverage (and knows its blind spots).

This is one of three layers. The other two are read-only credentials and
read-only transports (socket proxy, SSH forced command); see ``deploy/``.
"""

from __future__ import annotations

import inspect
from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar

from pydantic import BaseModel, ConfigDict

from labwarden.model.lab import LabModel

READ_ONLY_PREFIXES = ("get_", "list_", "read_", "fetch_", "parse_", "collect", "describe")


class ReadOnlyViolation(Exception):
    """Raised when code attempts something that could modify a target system."""


class NoOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Collector(ABC):
    #: Plugin identifier used in config files, e.g. ``plugin: pihole``.
    plugin: ClassVar[str]
    #: One-line human description.
    description: ClassVar[str] = ""
    #: LabModel collections this collector can populate, e.g. ``{"devices", "containers"}``.
    provides: ClassVar[frozenset[str]] = frozenset()
    #: Pydantic model validating this collector's ``options:`` block.
    Options: ClassVar[type[BaseModel]] = NoOptions

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        for attr, value in vars(cls).items():
            if attr.startswith("_") or inspect.isclass(value):
                continue
            func = value.__func__ if isinstance(value, classmethod | staticmethod) else value
            if callable(func) and not attr.startswith(READ_ONLY_PREFIXES):
                raise ReadOnlyViolation(
                    f"{cls.__name__}.{attr}: collectors may only define read-only public "
                    f"methods (names starting with {', '.join(READ_ONLY_PREFIXES)}). "
                    "Prefix internal helpers with '_'."
                )
        unknown = cls.provides - set(LabModel.kinds())
        if unknown:
            raise TypeError(f"{cls.__name__}.provides has unknown collections: {sorted(unknown)}")

    def __init__(self, target: str, options: BaseModel, base_dir: Path) -> None:
        self.target = target
        self.options = options
        # Directory relative paths in options are resolved against (the config file's dir).
        self.base_dir = base_dir

    @abstractmethod
    def collect(self) -> LabModel:
        """Read the source and return what was observed. Must not modify anything."""
