"""The read-only tools LabWarden gives to an AI: one implementation, two front ends.

``LabToolkit`` methods return plain JSON-ready data. The MCP server
(``labwarden.mcp_server``) registers them as MCP tools, and the agent loop
(Phase 1 step 7) calls the same methods in-process. Tool descriptions are the
method docstrings, written for an LLM: what the tool returns, when to use it,
and what it can't tell you.

Nothing here changes a system:

* inventory tools read the latest snapshot from SQLite
* probe tools send a few packets, rate-limited (see ``labwarden.probes``)
* collector options (which hold credentials) are never returned
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Annotated, Any, Literal

import paramiko
from mcp.server.mcpserver.exceptions import ToolError as McpToolError
from pydantic import Field

from labwarden.collectors.linux_ssh import SshCommandError
from labwarden.collectors.registry import get_collector
from labwarden.config import Config
from labwarden.model.diff import diff_models
from labwarden.model.entities import Entity
from labwarden.model.lab import LabModel
from labwarden.model.store import Snapshot, SnapshotStore
from labwarden.probes import (
    DEFAULT_LIMITER,
    LocalExecutor,
    ProbeResult,
    RateLimiter,
    dns_resolve,
    http_head,
    ping,
    remote_executor,
    tcp_connect,
    traceroute,
)

MAX_RESULTS = 200

Limit = Annotated[int, Field(ge=1, le=MAX_RESULTS, description="Maximum results to return.")]
FromHost = Annotated[
    str | None,
    Field(
        description=(
            "Run the probe from this linux_ssh target (see lab_summary) instead of from the "
            "LabWarden host. Use it to test 'from the NAS's point of view'."
        )
    ),
]


class ToolError(McpToolError):
    """A tool was called in a way it can't answer; the message is shown to the model.

    It subclasses the MCP SDK's ToolError, because that's the only exception
    whose message the SDK passes to the model (anything else becomes a generic
    "Error executing tool").
    """


@dataclass(frozen=True)
class ToolSpec:
    name: str
    #: "inventory": reads stored snapshots. "probe": sends packets on the network.
    kind: Literal["inventory", "probe"]


#: Every tool, in the order they're listed to the model.
TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec("lab_summary", "inventory"),
    ToolSpec("inventory_search", "inventory"),
    ToolSpec("device_get", "inventory"),
    ToolSpec("network_subnets", "inventory"),
    ToolSpec("routes_get", "inventory"),
    ToolSpec("dns_records", "inventory"),
    ToolSpec("docker_containers", "inventory"),
    ToolSpec("services_list", "inventory"),
    ToolSpec("firewall_rules", "inventory"),
    ToolSpec("snapshot_list", "inventory"),
    ToolSpec("snapshot_diff", "inventory"),
    ToolSpec("probe_ping", "probe"),
    ToolSpec("probe_traceroute", "probe"),
    ToolSpec("probe_dns", "probe"),
    ToolSpec("probe_tcp", "probe"),
    ToolSpec("probe_http", "probe"),
)


def _dump(entity: Entity) -> dict[str, Any]:
    return entity.model_dump(mode="json", exclude_none=True)


def _capped(items: list[Any], limit: int, key: str) -> dict[str, Any]:
    return {key: items[:limit], "count": len(items), "truncated": len(items) > limit}


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return [] if value is None or isinstance(value, bool) else [str(value)]


class LabToolkit:
    def __init__(
        self,
        config: Config,
        store: SnapshotStore | None = None,
        limiter: RateLimiter = DEFAULT_LIMITER,
    ) -> None:
        self._config = config
        self._store = store or SnapshotStore(config.snapshot_db)
        self._limiter = limiter

    def callables(self) -> dict[str, Callable[..., Any]]:
        """Tool name -> bound method, for registering with MCP or an agent loop."""
        return {spec.name: getattr(self, spec.name) for spec in TOOLS}

    # --- helpers ------------------------------------------------------------------------------

    def _latest(self) -> Snapshot:
        snap = self._store.latest()
        if snap is None:
            raise ToolError("No snapshots yet. Run `labwarden collect` first.")
        return snap

    def _snapshot_meta(self, snap: Snapshot) -> dict[str, Any]:
        age = datetime.now(UTC) - snap.taken_at.astimezone(UTC)
        return {
            "snapshot_id": snap.id,
            "taken_at": snap.taken_at.isoformat(),
            "age_minutes": round(age.total_seconds() / 60, 1),
        }

    # --- inventory ----------------------------------------------------------------------------

    def lab_summary(self) -> dict[str, Any]:
        """Start here. Overview of the lab from the latest snapshot.

        Returns the snapshot's ID, age and per-collection counts, every device
        (name, kind, management IP, roles), the configured collector targets and
        what each one covers, targets that failed in the last collection, and
        `blind_spots`: collections no collector observes live (the hand-written
        inventory may still declare some of them, but nothing checks them). Data
        can be stale (check `age_minutes`); use the probe_* tools for live state.
        """
        snap = self._latest()
        targets = []
        covered: set[str] = set()
        for t in self._config.targets:
            cls = get_collector(t.plugin)
            provides = sorted(cls.provides) if cls else []
            # The manual inventory can declare anything, but it observes nothing, so
            # it doesn't count as coverage.
            if t.enabled and t.plugin != "manual":
                covered.update(provides)
            targets.append(
                {"name": t.name, "plugin": t.plugin, "enabled": t.enabled, "provides": provides}
            )
        return {
            **self._snapshot_meta(snap),
            "counts": {k: v for k, v in snap.model.counts().items() if v},
            "devices": [
                {
                    "name": d.name,
                    "kind": d.kind,
                    "management_ip": str(d.management_ip) if d.management_ip else None,
                    "roles": d.roles,
                    "source": d.source,
                }
                for d in snap.model.devices
            ],
            "targets": targets,
            "failed_targets": snap.errors,
            "probe_sources": [
                t.name for t in self._config.targets if t.plugin == "linux_ssh" and t.enabled
            ],
            "blind_spots": sorted(set(LabModel.kinds()) - covered - {"log_events"}),
        }

    def inventory_search(
        self,
        query: Annotated[
            str,
            Field(
                min_length=1,
                description="Text to look for: a name, IP, MAC, image, port... (case-insensitive).",
            ),
        ],
        kind: Annotated[
            str | None,
            Field(description="Only search this collection, e.g. 'devices' or 'containers'."),
        ] = None,
        limit: Limit = 25,
    ) -> dict[str, Any]:
        """Find anything in the latest snapshot that mentions `query`.

        Searches every field of every entity (devices, interfaces, addresses,
        subnets, routes, DNS records, containers, services, firewall rules, ...).
        Use it when you don't know which collection holds what you need.
        """
        model = self._latest().model
        if kind is not None and kind not in LabModel.kinds():
            raise ToolError(f"unknown kind {kind!r}; choose from {', '.join(LabModel.kinds())}")
        needle = query.lower()
        hits = []
        for k, entity in model.entities():
            if kind and k != kind:
                continue
            data = _dump(entity)
            if any(needle in s.lower() for s in _strings(data)):
                hits.append({"kind": k, "entity": data})
        return _capped(hits, limit, "results")

    def device_get(
        self,
        name_or_ip: Annotated[
            str, Field(min_length=1, description="Device name, or any of its IP addresses.")
        ],
    ) -> dict[str, Any]:
        """Everything known about one device: the device record plus its interfaces,
        addresses, routes, listening services, containers (if it's a Docker host)
        and firewall rules.

        Matches the exact name first, then any device that owns that IP. Several
        collectors may describe the same physical box under different names (e.g.
        inventory 'pihole' and discovery 'pihole.lan'); all matches are returned.
        """
        model = self._latest().model
        names = self._resolve_devices(model, name_or_ip)
        if not names:
            close = [d.name for d in model.devices if name_or_ip.lower() in d.name.lower()]
            hint = f" Similar names: {', '.join(close[:10])}." if close else ""
            raise ToolError(f"No device named or addressed {name_or_ip!r}.{hint}")
        return {"devices": [self._device_view(model, n) for n in names]}

    def _resolve_devices(self, model: LabModel, needle: str) -> list[str]:
        names = [needle] if model.device(needle) else []
        try:
            ip = ip_address(needle)
        except ValueError:
            return names
        for d in model.devices:
            if d.management_ip == ip and d.name not in names:
                names.append(d.name)
        for a in model.addresses:
            if a.address.ip == ip and a.device not in names:
                names.append(a.device)
        return names

    def _device_view(self, model: LabModel, name: str) -> dict[str, Any]:
        device = model.device(name)
        return {
            "device": _dump(device) if device else {"name": name, "note": "no device record"},
            "interfaces": [_dump(e) for e in model.interfaces if e.device == name],
            "addresses": [_dump(e) for e in model.addresses if e.device == name],
            "routes": [_dump(e) for e in model.routes if e.device == name],
            "services": [_dump(e) for e in model.services if e.device == name],
            "containers": [_dump(e) for e in model.containers if e.host == name],
            "firewall_rules": [_dump(e) for e in model.firewall_rules if e.device == name],
        }

    def network_subnets(self) -> dict[str, Any]:
        """The IP plan: subnets (CIDR, gateway, DNS servers, VLAN), VLANs, and DHCP
        scopes (which server hands out which range, with which gateway and DNS)."""
        model = self._latest().model
        return {
            "subnets": [_dump(e) for e in model.subnets],
            "vlans": [_dump(e) for e in model.vlans],
            "dhcp_scopes": [_dump(e) for e in model.dhcp_scopes],
        }

    def routes_get(
        self,
        device: Annotated[str | None, Field(description="Only this device's routes.")] = None,
        limit: Limit = 100,
    ) -> dict[str, Any]:
        """Routing tables: destination, gateway, interface and metric per device.
        A route to 0.0.0.0/0 is the default gateway."""
        routes = [_dump(r) for r in self._latest().model.routes if device in (None, r.device)]
        return _capped(routes, limit, "routes")

    def dns_records(
        self,
        name_contains: Annotated[
            str | None, Field(description="Only records whose name contains this text.")
        ] = None,
        limit: Limit = 100,
    ) -> dict[str, Any]:
        """Local DNS records (A, AAAA, CNAME) defined on the lab's DNS servers, e.g.
        Pi-hole local DNS. Doesn't do lookups; use probe_dns for that."""
        needle = (name_contains or "").lower()
        records = [_dump(r) for r in self._latest().model.dns_records if needle in r.name.lower()]
        return _capped(records, limit, "records")

    def docker_containers(
        self,
        host: Annotated[str | None, Field(description="Only containers on this host.")] = None,
        exposed_only: Annotated[
            bool,
            Field(description="Only containers that publish a port on all host interfaces."),
        ] = False,
        limit: Limit = 100,
    ) -> dict[str, Any]:
        """Docker containers: image, state, networks, published ports, privileged
        flag, user and restart policy. Each container also gets `exposed_ports`
        (host ports reachable on every interface) and `runs_as_root`."""
        result = []
        for c in self._latest().model.containers:
            if host not in (None, c.host):
                continue
            exposed = [p.host_port for p in c.ports if p.is_exposed_on_all_interfaces()]
            if exposed_only and not exposed:
                continue
            result.append(
                {
                    **_dump(c),
                    "exposed_ports": sorted(set(exposed)),
                    "runs_as_root": c.user in (None, "root", "0") or str(c.user).startswith("0:"),
                }
            )
        return _capped(result, limit, "containers")

    def services_list(
        self,
        device: Annotated[str | None, Field(description="Only this device.")] = None,
        port: Annotated[
            int | None, Field(ge=0, le=65535, description="Only this port number.")
        ] = None,
        limit: Limit = 100,
    ) -> dict[str, Any]:
        """Listening sockets seen on devices (from SSH `ss`, Docker publishes and
        nmap): device, address, port, protocol and process. Answers "what listens
        on port 445?" or "what is exposed on the NAS?"."""
        services = [
            _dump(s)
            for s in self._latest().model.services
            if device in (None, s.device) and port in (None, s.port)
        ]
        return _capped(services, limit, "services")

    def firewall_rules(
        self,
        device: Annotated[str | None, Field(description="Only this device's rules.")] = None,
        chain: Annotated[str | None, Field(description="Only this chain/interface.")] = None,
        limit: Limit = 200,
    ) -> dict[str, Any]:
        """Firewall rules in evaluation order per chain: action, direction, protocol,
        source, destination and ports. A rule described as 'default policy' is what
        happens when nothing else matches. Parsing is partial in this version;
        unknown match conditions are kept in `description`, so read it."""
        rules = [
            _dump(r)
            for r in self._latest().model.firewall_rules
            if device in (None, r.device) and chain in (None, r.chain)
        ]
        return _capped(rules, limit, "rules")

    def snapshot_list(self, limit: Limit = 20) -> dict[str, Any]:
        """Past snapshots, newest first: ID, time, label, and which targets failed."""
        return {
            "snapshots": [
                {
                    "id": s.id,
                    "taken_at": s.taken_at.isoformat(),
                    "label": s.label,
                    "failed_targets": sorted(s.errors),
                }
                for s in self._store.history(limit)
            ]
        }

    def snapshot_diff(
        self,
        before: Annotated[
            int | None, Field(description="Older snapshot ID. Default: the one before `after`.")
        ] = None,
        after: Annotated[
            int | None, Field(description="Newer snapshot ID. Default: latest.")
        ] = None,
        limit: Limit = 100,
    ) -> dict[str, Any]:
        """What changed between two snapshots: entities added, removed, or changed
        (with each changed field's before and after value). Use it for "what changed
        since yesterday?" and to verify that a fix took effect."""
        new = self._store.get(after) if after is not None else self._store.latest()
        if new is None:
            raise ToolError(f"snapshot {after} not found" if after else "no snapshots yet")
        if before is not None:
            old = self._store.get(before)
        else:
            older = [s for s in self._store.history(MAX_RESULTS) if s.id < new.id]
            old = self._store.get(older[0].id) if older else None
        if old is None:
            raise ToolError("need an older snapshot to compare with; run `labwarden collect` again")
        changes = [
            {
                "status": c.status,
                "kind": c.kind,
                "key": " / ".join(c.key),
                "fields": [f.model_dump(mode="json") for f in c.changes],
            }
            for c in diff_models(old.model, new.model).changes
        ]
        return {"before": old.id, "after": new.id, **_capped(changes, limit, "changes")}

    # --- live probes ----------------------------------------------------------------------------

    def _probe(self, from_host: str | None, fn: Callable[..., ProbeResult], *args: Any, **kw: Any):
        try:
            if from_host:
                try:
                    executor = remote_executor(self._config, from_host)
                except LookupError as exc:
                    raise ToolError(str(exc)) from exc
                try:
                    with executor as ex:
                        result = fn(*args, executor=ex, limiter=self._limiter, **kw)
                except (OSError, paramiko.SSHException, SshCommandError) as exc:
                    raise ToolError(f"could not run the probe from {from_host}: {exc}") from exc
            else:
                result = fn(*args, executor=LocalExecutor(), limiter=self._limiter, **kw)
        except ValueError as exc:
            raise ToolError(f"invalid input: {exc}") from exc
        return result.model_dump(mode="json")

    def probe_ping(
        self,
        host: Annotated[str, Field(description="Host name or IP to ping.")],
        count: Annotated[int, Field(ge=1, le=5, description="Echo requests to send.")] = 3,
        from_host: FromHost = None,
    ) -> dict[str, Any]:
        """Live ICMP ping. `ok` if any echo reply came back. Many devices and
        firewalls drop ping, so no reply doesn't prove a host is down; confirm with
        probe_tcp on a port it should serve."""
        return self._probe(from_host, ping, host, count=count)

    def probe_traceroute(
        self,
        host: Annotated[str, Field(description="Destination host name or IP.")],
        max_hops: Annotated[int, Field(ge=1, le=30, description="Maximum hops.")] = 20,
        from_host: FromHost = None,
    ) -> dict[str, Any]:
        """Live traceroute: the routers on the path and where replies stop. Shows
        which gateway traffic leaves through and the hop where a path breaks."""
        return self._probe(from_host, traceroute, host, max_hops=max_hops)

    def probe_dns(
        self,
        name: Annotated[str, Field(description="DNS name to look up.")],
        record_type: Annotated[
            Literal["A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SOA", "SRV"],
            Field(description="Record type."),
        ] = "A",
        server: Annotated[
            str | None,
            Field(description="IP of the DNS server to ask (e.g. the Pi-hole). Default: system."),
        ] = None,
        from_host: FromHost = None,
    ) -> dict[str, Any]:
        """Live DNS lookup, optionally against one specific server. Status is
        NOERROR, NXDOMAIN, SERVFAIL or TIMEOUT. `blocked_hint` is true when the
        answer is 0.0.0.0 or ::, which is how Pi-hole answers for blocked domains.
        Compare against a public resolver (e.g. 1.1.1.1) to isolate the faulty layer."""
        return self._probe(from_host, dns_resolve, name, record_type=record_type, server=server)

    def probe_tcp(
        self,
        host: Annotated[str, Field(description="Host name or IP.")],
        port: Annotated[int, Field(ge=1, le=65535, description="TCP port.")],
        from_host: FromHost = None,
    ) -> dict[str, Any]:
        """Live TCP connect test (handshake only, no data sent). State is open,
        refused (host up, nothing listening), timeout (filtered or host down),
        unresolved or unreachable."""
        return self._probe(from_host, tcp_connect, host, port)

    def probe_http(
        self,
        url: Annotated[str, Field(description="http:// or https:// URL.")],
        from_host: FromHost = None,
    ) -> dict[str, Any]:
        """Live HTTP HEAD request: status code, server header and redirect target
        (redirects are reported, not followed). TLS errors are reported as such."""
        return self._probe(from_host, http_head, url)
