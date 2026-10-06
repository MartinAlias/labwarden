"""The LabModel: one normalized picture of the whole homelab."""

from __future__ import annotations

from collections.abc import Iterator

from pydantic import BaseModel, ConfigDict, Field

from labwarden.model.entities import (
    Address,
    Container,
    Device,
    DhcpScope,
    DnsRecord,
    Entity,
    FirewallRule,
    Interface,
    Link,
    LogEvent,
    NatRule,
    Route,
    Service,
    Subnet,
    Vlan,
)


class LabModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    devices: list[Device] = Field(default_factory=list)
    interfaces: list[Interface] = Field(default_factory=list)
    addresses: list[Address] = Field(default_factory=list)
    vlans: list[Vlan] = Field(default_factory=list)
    subnets: list[Subnet] = Field(default_factory=list)
    dhcp_scopes: list[DhcpScope] = Field(default_factory=list)
    routes: list[Route] = Field(default_factory=list)
    dns_records: list[DnsRecord] = Field(default_factory=list)
    firewall_rules: list[FirewallRule] = Field(default_factory=list)
    nat_rules: list[NatRule] = Field(default_factory=list)
    containers: list[Container] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    links: list[Link] = Field(default_factory=list)
    log_events: list[LogEvent] = Field(default_factory=list)

    @classmethod
    def kinds(cls) -> list[str]:
        """Names of every entity collection, e.g. ``["devices", "interfaces", ...]``."""
        return list(cls.model_fields)

    def entities(self) -> Iterator[tuple[str, Entity]]:
        for kind in self.kinds():
            for entity in getattr(self, kind):
                yield kind, entity

    def counts(self) -> dict[str, int]:
        return {kind: len(getattr(self, kind)) for kind in self.kinds()}

    def stamp_source(self, source: str) -> None:
        """Mark every entity that has no source yet as coming from ``source``."""
        for _, entity in self.entities():
            if entity.source is None:
                entity.source = source

    def merge(self, other: LabModel) -> None:
        """Append another model's entities into this one.

        If two collectors report the same entity key, the first one wins and the
        duplicate is dropped. Conflicts are rare in practice (each collector owns
        its own devices), and keeping the first keeps results deterministic in
        config order.
        """
        for kind in self.kinds():
            mine: list[Entity] = getattr(self, kind)
            seen = {e.key() for e in mine}
            for entity in getattr(other, kind):
                if entity.key() not in seen:
                    mine.append(entity)
                    seen.add(entity.key())

    def device(self, name: str) -> Device | None:
        return next((d for d in self.devices if d.name == name), None)
