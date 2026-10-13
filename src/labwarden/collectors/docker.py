"""Docker Engine API through a GET-only docker-socket-proxy.

LabWarden never mounts ``/var/run/docker.sock``. It talks plain HTTP to
`tecnativa/docker-socket-proxy <https://github.com/Tecnativa/docker-socket-proxy>`_
started with ``CONTAINERS=1 NETWORKS=1 POST=0``, so the transport itself can't
change anything. On top of that, ``_guard_request`` refuses every non-GET
request before it leaves the process. The docker SDK isn't used, because its
API surface makes a mutating call one typo away.

What it reads (all GET):

* ``/containers/json?all=1``, then ``/containers/{id}/json`` for each container:
  image, state, networks, published ports, privileged, user, restart policy.
* ``/networks``: each network's subnet and gateway. Optional; skipped with a
  warning if the proxy has ``NETWORKS=0``.
* ``/version``: engine version for the host device. Optional, same handling.

Container environment variables and labels often hold passwords and tokens.
They are never copied into the Lab Model. Scrub them from recorded fixtures.

Config::

    - name: docker-server
      plugin: docker
      options:
        url: tcp://192.168.20.10:2375    # the socket proxy; tcp:// means http://
"""

from __future__ import annotations

import logging
from ipaddress import ip_address, ip_network
from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, field_validator

from labwarden.collectors.base import Collector
from labwarden.collectors.http import read_only_guard
from labwarden.model.entities import Container, Device, DeviceKind, PortMapping, Service, Subnet
from labwarden.model.lab import LabModel

log = logging.getLogger(__name__)

_guard_request = read_only_guard("docker")


class DockerOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str
    verify_tls: bool = True
    timeout: float = 10.0
    #: Name of the Docker host in the Lab Model. Defaults to the target name.
    host_name: str | None = None

    @field_validator("url")
    @classmethod
    def _proxy_url(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme == "unix":
            raise ValueError(
                "LabWarden reads Docker only through docker-socket-proxy, never the raw "
                "socket. Point url at the proxy, e.g. tcp://192.168.20.10:2375"
            )
        scheme = "http" if parts.scheme == "tcp" else parts.scheme
        if scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("url must look like tcp://host:2375 or http://host:2375")
        if parts.path.strip("/"):
            raise ValueError("url must not have a path")
        return f"{scheme}://{parts.netloc}"


class DockerError(Exception):
    """The proxy answered, but not with something we can use."""


class DockerCollector(Collector):
    plugin = "docker"
    description = "Docker containers, published ports and networks via a GET-only socket proxy."
    provides = frozenset({"devices", "containers", "subnets", "services"})
    Options = DockerOptions

    #: Tests swap in an ``httpx.MockTransport``.
    _transport: httpx.BaseTransport | None = None

    def collect(self) -> LabModel:
        opts: DockerOptions = self.options
        with httpx.Client(
            base_url=opts.url,
            timeout=opts.timeout,
            verify=opts.verify_tls,
            transport=self._transport,
            event_hooks={"request": [_guard_request]},
        ) as client:
            summaries = self._get(
                client, "/containers/json", params={"all": "1"}, section="CONTAINERS"
            )
            inspected = [self._get(client, f"/containers/{c['Id']}/json") for c in summaries]
            networks = self._get_optional(client, "/networks", section="NETWORKS") or []
            version = self._get_optional(client, "/version", section="VERSION") or {}
        return parse_docker(
            host=opts.host_name or self.target,
            containers=inspected,
            networks=networks,
            version=version,
        )

    def _get(
        self,
        client: httpx.Client,
        path: str,
        params: dict[str, str] | None = None,
        section: str | None = None,
    ) -> Any:
        resp = client.get(path, params=params)
        if resp.status_code == 403 and section:
            raise DockerError(f"the socket proxy blocks {path}; start it with {section}=1")
        resp.raise_for_status()
        try:
            return resp.json()
        except ValueError as exc:
            raise DockerError(f"{path}: response is not JSON") from exc

    def _get_optional(self, client: httpx.Client, path: str, section: str) -> Any:
        try:
            return self._get(client, path, section=section)
        except DockerError as exc:
            log.warning("%s: %s; continuing without it", self.target, exc)
            return None


def parse_docker(
    *,
    host: str,
    containers: list[dict[str, Any]],
    networks: list[dict[str, Any]],
    version: dict[str, Any],
) -> LabModel:
    """Translate Docker API responses into a LabModel. Pure, so tests need no HTTP."""
    model = LabModel()
    if version.get("Version"):
        platform = "/".join(v for v in (version.get("Os"), version.get("Arch")) if v)
        engine = f"Docker {version['Version']}"
        model.devices.append(
            Device(
                name=host,
                kind=DeviceKind.SERVER,
                os=f"{engine} ({platform})" if platform else engine,
                roles=["docker"],
            )
        )

    for raw in sorted(containers, key=lambda c: c.get("Name", "")):
        container = _container(host, raw)
        model.containers.append(container)
        if container.state == "running":
            model.services.extend(_published_services(host, container))

    for net in sorted(networks, key=lambda n: n.get("Name", "")):
        for cfg in (net.get("IPAM") or {}).get("Config") or []:
            subnet = _subnet(host, net.get("Name", "?"), cfg)
            if subnet is not None:
                model.subnets.append(subnet)
    return model


def _container(host: str, raw: dict[str, Any]) -> Container:
    config = raw.get("Config") or {}
    host_config = raw.get("HostConfig") or {}
    settings = raw.get("NetworkSettings") or {}
    state = (raw.get("State") or {}).get("Status") or "unknown"
    restart = (host_config.get("RestartPolicy") or {}).get("Name") or None
    return Container(
        host=host,
        name=raw.get("Name", "").lstrip("/") or raw.get("Id", "?")[:12],
        image=config.get("Image") or raw.get("Image", "?"),
        state=state,
        networks=sorted(settings.get("Networks") or {}),
        ports=_ports(raw, running=state == "running"),
        privileged=bool(host_config.get("Privileged")),
        user=config.get("User") or None,  # empty means the image default, usually root
        restart_policy=restart,
    )


def _ports(raw: dict[str, Any], *, running: bool) -> list[PortMapping]:
    """Published ports.

    A running container's ``NetworkSettings.Ports`` holds the real bindings,
    including randomly assigned host ports. A stopped container has none, so
    fall back to what it's configured to publish, so stopping a container
    doesn't show up as "port removed" in diffs.
    """
    actual = (raw.get("NetworkSettings") or {}).get("Ports")
    if running and actual:
        source: dict[str, Any] = actual
    else:
        exposed = dict.fromkeys((raw.get("Config") or {}).get("ExposedPorts") or {})
        bindings = (raw.get("HostConfig") or {}).get("PortBindings") or {}
        source = {**exposed, **bindings}

    ports = []
    for key, binds in source.items():
        port, _, proto = key.partition("/")
        if proto not in ("tcp", "udp") or not port.isdigit():
            continue  # sctp has no place in the model yet
        if not binds:
            ports.append(PortMapping(container_port=int(port), protocol=proto))
            continue
        for bind in binds:
            host_port = bind.get("HostPort") or ""
            ports.append(
                PortMapping(
                    container_port=int(port),
                    protocol=proto,
                    host_ip=bind.get("HostIp") or None,
                    host_port=int(host_port) if host_port.isdigit() else None,
                )
            )
    return sorted(
        ports, key=lambda p: (p.container_port, p.protocol, str(p.host_ip), p.host_port or 0)
    )


def _published_services(host: str, container: Container) -> list[Service]:
    """Host sockets a running container listens on through a port publish."""
    services = []
    for p in container.ports:
        if p.host_port is None:
            continue
        services.append(
            Service(
                device=host,
                address=p.host_ip if p.host_ip is not None else ip_address("0.0.0.0"),
                port=p.host_port,
                protocol=p.protocol,
                process=f"docker:{container.name}",
            )
        )
    return services


def _subnet(host: str, name: str, cfg: dict[str, Any]) -> Subnet | None:
    try:
        cidr = ip_network(cfg.get("Subnet", ""), strict=False)
    except ValueError:
        return None
    gateway = cfg.get("Gateway") or None
    try:
        gateway = ip_address(gateway) if gateway else None
    except ValueError:
        gateway = None
    return Subnet(cidr=cidr, name=f"docker:{host}/{name}", gateway=gateway)
