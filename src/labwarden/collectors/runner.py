"""Runs every configured collector target and merges the results into one LabModel."""

from __future__ import annotations

from dataclasses import dataclass, field

from pydantic import ValidationError

from labwarden.collectors.base import Collector
from labwarden.collectors.registry import get_collector
from labwarden.config import Config, TargetConfig
from labwarden.model.lab import LabModel


@dataclass
class CollectionResult:
    model: LabModel = field(default_factory=LabModel)
    # Target name -> error message. A failing target never aborts the others.
    errors: dict[str, str] = field(default_factory=dict)


def build_collector(target: TargetConfig, config: Config) -> Collector:
    cls = get_collector(target.plugin)
    if cls is None:
        raise LookupError(f"unknown plugin {target.plugin!r}")
    try:
        options = cls.Options.model_validate(target.options)
    except ValidationError as exc:
        raise ValueError(f"invalid options: {exc}") from exc
    return cls(target.name, options, config.base_dir)


def run_collectors(config: Config) -> CollectionResult:
    result = CollectionResult()
    for target in config.targets:
        if not target.enabled:
            continue
        try:
            collector = build_collector(target, config)
            observed = collector.collect()
            _check_manifest(collector, observed)
        except Exception as exc:
            result.errors[target.name] = f"{type(exc).__name__}: {exc}"
            continue
        observed.stamp_source(target.name)
        result.model.merge(observed)
    return result


def _check_manifest(collector: Collector, observed: LabModel) -> None:
    undeclared = {k for k, n in observed.counts().items() if n} - collector.provides
    if undeclared:
        raise RuntimeError(
            f"plugin {collector.plugin!r} returned collections it does not declare in "
            f"`provides`: {sorted(undeclared)}"
        )
