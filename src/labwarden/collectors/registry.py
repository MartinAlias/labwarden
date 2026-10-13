"""Discovers collector plugins: built-ins plus anything registered via entry points."""

from __future__ import annotations

import logging
from functools import cache
from importlib.metadata import entry_points

from labwarden.collectors.base import Collector
from labwarden.collectors.manual import ManualCollector
from labwarden.collectors.pihole import PiholeCollector

ENTRY_POINT_GROUP = "labwarden.collectors"

log = logging.getLogger(__name__)

_BUILTINS: dict[str, type[Collector]] = {
    ManualCollector.plugin: ManualCollector,
    PiholeCollector.plugin: PiholeCollector,
}


@cache
def available_collectors() -> dict[str, type[Collector]]:
    found = dict(_BUILTINS)
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        if ep.name in found:
            continue
        try:
            cls = ep.load()
        except Exception as exc:  # a broken third-party plugin must not break the rest
            log.warning("failed to load collector plugin %r: %s", ep.name, exc)
            continue
        if not (isinstance(cls, type) and issubclass(cls, Collector)):
            log.warning("plugin %r does not point at a Collector subclass", ep.name)
            continue
        found[ep.name] = cls
    return found


def get_collector(plugin: str) -> type[Collector] | None:
    return available_collectors().get(plugin)
