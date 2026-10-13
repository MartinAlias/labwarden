"""The result every probe returns."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ProbeResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    probe: Literal["ping", "traceroute", "dns", "tcp", "http"]
    #: What was probed, e.g. "192.168.20.2", "pihole.lan A", "nas:445", a URL.
    target: str
    #: "local", or the linux_ssh target the probe ran from.
    source: str
    ok: bool
    #: One plain-English line, written to be read by a person or an LLM.
    summary: str
    #: Probe-specific facts (rtt, hops, answers, status code, ...).
    data: dict[str, Any] = Field(default_factory=dict)
    duration_ms: float
    error: str | None = None
