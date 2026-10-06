"""Vendor-neutral entities that make up the Lab Model.

Every collector translates vendor-specific data into these types. Diagnosis,
documentation and advice only ever read these, never raw vendor formats.

Each entity declares ``_key_fields``: the fields that identify "the same thing"
across two snapshots. Snapshot diffs match entities by this key and then report
field-level changes.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, IPvAnyInterface, IPvAnyNetwork

Protocol = Literal["tcp", "udp", "icmp", "any"]


class Entity(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    _key_fields: ClassVar[tuple[str, ...]] = ()

    # Name of the collector target that reported this entity (stamped by the runner).
    source: str | None = None

    def key(self) -> tuple[str, ...]:
        return tuple(str(getattr(self, f)) for f in self._key_fields)


class DeviceKind(StrEnum):
    ROUTER = "router"
    FIREWALL = "firewall"
    SWITCH = "switch"
    ACCESS_POINT = "access_point"
    SERVER = "server"
    NAS = "nas"
    HYPERVISOR = "hypervisor"
    VM = "vm"
    CLIENT = "client"
    IOT = "iot"
    OTHER = "other"


class HardwareSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cpu: str | None = None
    memory_mb: int | None = None
    nic_count: int | None = None
    nic_speeds_mbps: list[int] = Field(default_factory=list)
    # Free-form capability tags the advisor reasons about, e.g. "vlan_802.1q", "poe".
    capabilities: list[str] = Field(default_factory=list)
    notes: str | None = None


class Device(Entity):
    _key_fields = ("name",)

    name: str
    kind: DeviceKind = DeviceKind.OTHER
    vendor: str | None = None
    model: str | None = None
    os: str | None = None
    management_ip: IPvAnyAddress | None = None
    roles: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    hardware: HardwareSpec | None = None
    notes: str | None = None


class Interface(Entity):
    _key_fields = ("device", "name")

    device: str
    name: str
    mac: str | None = None
    state: Literal["up", "down", "unknown"] = "unknown"
    mtu: int | None = None
    speed_mbps: int | None = None
    vlan_id: int | None = Field(default=None, ge=1, le=4094)


class Address(Entity):
    _key_fields = ("device", "address")

    device: str
    interface: str | None = None
    address: IPvAnyInterface  # IP with prefix, e.g. 192.168.1.10/24
    dhcp: bool | None = None


class Vlan(Entity):
    _key_fields = ("vlan_id",)

    vlan_id: int = Field(ge=1, le=4094)
    name: str | None = None
    purpose: str | None = None


class Subnet(Entity):
    _key_fields = ("cidr",)

    cidr: IPvAnyNetwork
    name: str | None = None
    vlan_id: int | None = Field(default=None, ge=1, le=4094)
    gateway: IPvAnyAddress | None = None
    dns_servers: list[IPvAnyAddress] = Field(default_factory=list)


class DhcpScope(Entity):
    _key_fields = ("server", "subnet")

    server: str
    subnet: IPvAnyNetwork
    range_start: IPvAnyAddress
    range_end: IPvAnyAddress
    gateway: IPvAnyAddress | None = None
    dns_servers: list[IPvAnyAddress] = Field(default_factory=list)


class Route(Entity):
    _key_fields = ("device", "destination", "gateway")

    device: str
    destination: IPvAnyNetwork
    gateway: IPvAnyAddress | None = None
    interface: str | None = None
    metric: int | None = None


class DnsRecord(Entity):
    _key_fields = ("server", "name", "type", "value")

    server: str
    name: str
    type: str = "A"
    value: str


class FirewallRule(Entity):
    _key_fields = ("device", "chain", "order")

    device: str
    chain: str  # interface or chain name, e.g. "LAN", "input", "forward"
    order: int  # evaluation order within the chain
    action: Literal["allow", "block", "reject"]
    direction: Literal["in", "out", "any"] = "in"
    protocol: Protocol = "any"
    src: str = "any"
    src_port: str | None = None
    dst: str = "any"
    dst_port: str | None = None
    enabled: bool = True
    description: str | None = None


class NatRule(Entity):
    _key_fields = ("device", "kind", "order")

    device: str
    kind: Literal["masquerade", "snat", "dnat", "port_forward"]
    order: int = 0
    interface: str | None = None
    protocol: Protocol = "any"
    src: str = "any"
    dst: str = "any"
    dst_port: str | None = None
    translate_to: str | None = None
    enabled: bool = True
    description: str | None = None


class PortMapping(BaseModel):
    model_config = ConfigDict(extra="forbid")

    container_port: int
    protocol: Literal["tcp", "udp"] = "tcp"
    host_ip: IPvAnyAddress | None = None
    host_port: int | None = None

    def is_exposed_on_all_interfaces(self) -> bool:
        return self.host_port is not None and (
            self.host_ip is None or self.host_ip in (IPv4Address("0.0.0.0"), IPv6Address("::"))
        )


class Container(Entity):
    _key_fields = ("host", "name")

    host: str
    name: str
    image: str
    state: str = "unknown"
    networks: list[str] = Field(default_factory=list)
    ports: list[PortMapping] = Field(default_factory=list)
    privileged: bool = False
    user: str | None = None
    restart_policy: str | None = None


class Service(Entity):
    """A listening socket observed on a device."""

    _key_fields = ("device", "address", "port", "protocol")

    device: str
    address: IPvAnyAddress
    port: int = Field(ge=0, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    process: str | None = None


class Link(Entity):
    """A physical or logical connection between two device interfaces."""

    _key_fields = ("a_device", "a_interface", "b_device", "b_interface")

    a_device: str
    b_device: str
    a_interface: str | None = None
    b_interface: str | None = None
    medium: str | None = None  # e.g. "ethernet", "wifi", "vlan-trunk"


class LogEvent(Entity):
    _key_fields = ("device", "timestamp", "message")

    device: str
    timestamp: datetime
    message: str
    severity: Literal["debug", "info", "notice", "warning", "error", "critical"] = "info"
    program: str | None = None
