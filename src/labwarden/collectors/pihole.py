"""Pi-hole v6 via its REST API.

What it reads (all GET):

* ``/api/config``: upstream DNS servers, local DNS records (``dns.hosts``),
  CNAMEs, and the embedded DHCP server's settings.
* ``/api/dhcp/leases``: current DHCP leases (empty when Pi-hole isn't doing DHCP).
* ``/api/info/version``: FTL/core versions, recorded as the device's ``os``.

Query statistics are deliberately not stored: the counters change on every
snapshot and would bury real changes in diff noise.

Authentication: ``POST /api/auth`` with the password returns a session id
(sent as the ``X-FTL-SID`` header). ``DELETE /api/auth`` ends the session when
we're done, because Pi-hole only allows a few concurrent sessions. These are the
only non-GET calls, they don't change configuration, and ``_guard_request``
refuses every other non-GET request before it leaves the process.

Use an **app password** (Settings → Web interface / API → Configure app
password) and leave ``webserver.api.app_sudo`` off. App-password sessions then
can't modify settings, which is the read-only credential layer. The collector
logs a warning if ``app_sudo`` is on.

Config::

    - name: pihole
      plugin: pihole
      options:
        url: http://192.168.1.2          # scheme://host[:port], no path
        password: ${PIHOLE_PASSWORD}     # omit if the Pi-hole has no password
        verify_tls: false                # for https:// with the default self-signed cert
"""

from __future__ import annotations

import logging
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_interface,
    ip_network,
)
from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, SecretStr, field_validator

from labwarden.collectors.base import Collector, ReadOnlyViolation
from labwarden.model.entities import Address, Device, DeviceKind, DhcpScope, DnsRecord, Subnet
from labwarden.model.lab import LabModel

log = logging.getLogger(__name__)

AUTH_PATH = "/api/auth"


class PiholeOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str
    password: SecretStr | None = None
    verify_tls: bool = True
    timeout: float = 10.0
    #: Name of the Pi-hole in the Lab Model. Defaults to the target name.
    device_name: str | None = None

    @field_validator("url")
    @classmethod
    def _base_url_only(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("url must look like http://192.168.1.2 or https://pi.hole")
        if parts.path.strip("/"):
            raise ValueError("url must not have a path; the API is always at /api")
        return f"{parts.scheme}://{parts.netloc}"


class PiholeError(Exception):
    """The Pi-hole answered, but not with something we can use."""


def _guard_request(request: httpx.Request) -> None:
    """Refuse every request that isn't a GET, except session login/logout."""
    if request.method == "GET":
        return
    if request.method in ("POST", "DELETE") and request.url.path == AUTH_PATH:
        return
    raise ReadOnlyViolation(f"pihole collector refused {request.method} {request.url.path}")


class PiholeCollector(Collector):
    plugin = "pihole"
    description = "Pi-hole v6 REST API: local DNS records, upstreams, DHCP scope and leases."
    provides = frozenset({"devices", "addresses", "subnets", "dhcp_scopes", "dns_records"})
    Options = PiholeOptions

    #: Tests swap in an ``httpx.MockTransport``.
    _transport: httpx.BaseTransport | None = None

    def collect(self) -> LabModel:
        opts: PiholeOptions = self.options
        with httpx.Client(
            base_url=opts.url,
            timeout=opts.timeout,
            verify=opts.verify_tls,
            transport=self._transport,
            event_hooks={"request": [_guard_request]},
        ) as client:
            if opts.password is not None:
                self._login(client, opts.password)
            try:
                config = self._get(client, "/api/config")["config"]
                leases = self._get(client, "/api/dhcp/leases").get("leases", [])
                version = self._get(client, "/api/info/version").get("version", {})
            finally:
                if "X-FTL-SID" in client.headers:
                    self._logout(client)

        if config.get("webserver", {}).get("api", {}).get("app_sudo"):
            log.warning(
                "%s: webserver.api.app_sudo is on, so the app password can change "
                "settings. Turn it off for a read-only credential.",
                self.target,
            )
        return parse_pihole(
            name=opts.device_name or self.target,
            management_ip=urlsplit(opts.url).hostname,
            config=config,
            leases=leases,
            version=version,
        )

    def _login(self, client: httpx.Client, password: SecretStr) -> None:
        resp = client.post(AUTH_PATH, json={"password": password.get_secret_value()})
        session = _json(resp).get("session") or {}
        if resp.status_code == 401 or not session.get("valid"):
            if session.get("totp"):
                raise PiholeError("Pi-hole wants a 2FA code; use an app password instead")
            raise PiholeError("Pi-hole rejected the password (check PIHOLE_PASSWORD)")
        resp.raise_for_status()
        client.headers["X-FTL-SID"] = session["sid"]

    def _logout(self, client: httpx.Client) -> None:
        try:
            client.delete(AUTH_PATH)
        except httpx.HTTPError as exc:  # the data is already in hand; don't fail on cleanup
            log.warning("%s: logout failed: %s", self.target, exc)

    def _get(self, client: httpx.Client, path: str) -> dict[str, Any]:
        resp = client.get(path)
        if resp.status_code == 401:
            raise PiholeError("Pi-hole requires a password (set options.password)")
        resp.raise_for_status()
        return _json(resp)


def _json(resp: httpx.Response) -> dict[str, Any]:
    try:
        data = resp.json()
    except ValueError as exc:
        raise PiholeError(f"{resp.request.url.path}: response is not JSON") from exc
    if not isinstance(data, dict):
        raise PiholeError(f"{resp.request.url.path}: expected a JSON object")
    return data


def parse_pihole(
    *,
    name: str,
    management_ip: str | None,
    config: dict[str, Any],
    leases: list[dict[str, Any]],
    version: dict[str, Any],
) -> LabModel:
    """Translate Pi-hole API responses into a LabModel. Pure, so tests need no HTTP."""
    dns = config.get("dns", {})
    dhcp = config.get("dhcp", {})
    server_ip = _ip_or_none(management_ip)

    domain = dns.get("domain")
    if isinstance(domain, dict):  # v6.1+: {"name": "lan", "local": true}; v6.0: "lan"
        domain = domain.get("name")

    tags = [f"dns-upstream:{u}" for u in dns.get("upstreams", [])]
    if domain:
        tags.append(f"dns-domain:{domain}")

    model = LabModel()
    model.devices.append(
        Device(
            name=name,
            kind=DeviceKind.SERVER,
            vendor="Pi-hole",
            os=_version_string(version),
            management_ip=server_ip,
            roles=["dns", "dhcp"] if dhcp.get("active") else ["dns"],
            tags=tags,
        )
    )
    model.dns_records.extend(_parse_hosts(name, dns.get("hosts", [])))
    model.dns_records.extend(_parse_cnames(name, dns.get("cnameRecords", [])))

    subnet = None
    if dhcp.get("active"):
        subnet = _dhcp_scope(name, dhcp, server_ip, model)

    for lease in leases:
        _add_lease(name, lease, subnet, model)
    return model


def _version_string(version: dict[str, Any]) -> str | None:
    parts = []
    for component, label in (("core", "core"), ("ftl", "FTL")):
        local = (version.get(component) or {}).get("local") or {}
        if local.get("version"):
            parts.append(f"{label} {local['version']}")
    return f"Pi-hole ({', '.join(parts)})" if parts else None


IP = IPv4Address | IPv6Address
Network = IPv4Network | IPv6Network


def _ip_or_none(value: object) -> IP | None:
    """Parse an IP; Pi-hole reports unset addresses as "" or 0.0.0.0."""
    if not value:
        return None
    try:
        ip = ip_address(str(value))
    except ValueError:
        return None
    return None if ip.is_unspecified else ip


def _parse_hosts(server: str, lines: list[str]) -> list[DnsRecord]:
    """``dns.hosts`` lines are hosts-file style: ``192.168.1.10 nas.lan nas``."""
    records = []
    for line in lines:
        fields = line.split()
        ip = _ip_or_none(fields[0]) if fields else None
        if ip is None or len(fields) < 2:
            log.warning("pihole: skipping unparseable dns.hosts entry %r", line)
            continue
        rtype = "A" if ip.version == 4 else "AAAA"
        records.extend(
            DnsRecord(server=server, name=host, type=rtype, value=str(ip)) for host in fields[1:]
        )
    return records


def _parse_cnames(server: str, lines: list[str]) -> list[DnsRecord]:
    """``dns.cnameRecords`` use dnsmasq syntax: ``alias[,alias...],target[,ttl]``."""
    records = []
    for line in lines:
        parts = [p.strip() for p in line.split(",") if p.strip()]
        if parts and parts[-1].isdigit():
            parts = parts[:-1]
        if len(parts) < 2:
            log.warning("pihole: skipping unparseable cnameRecords entry %r", line)
            continue
        *aliases, target = parts
        records.extend(
            DnsRecord(server=server, name=alias, type="CNAME", value=target) for alias in aliases
        )
    return records


def _dhcp_scope(
    server: str, dhcp: dict[str, Any], server_ip: IP | None, model: LabModel
) -> Network | None:
    start, end = _ip_or_none(dhcp.get("start")), _ip_or_none(dhcp.get("end"))
    if start is None or end is None:
        log.warning("pihole: DHCP is active but the range is not set")
        return None
    subnet = _scope_subnet(start, end, _ip_or_none(dhcp.get("netmask")))
    gateway = _ip_or_none(dhcp.get("router"))
    # Pi-hole's DHCP hands out itself as the DNS server.
    dns_servers = [server_ip] if server_ip is not None else []
    model.dhcp_scopes.append(
        DhcpScope(
            server=server,
            subnet=subnet,
            range_start=start,
            range_end=end,
            gateway=gateway,
            dns_servers=dns_servers,
        )
    )
    model.subnets.append(Subnet(cidr=subnet, gateway=gateway, dns_servers=dns_servers))
    return subnet


def _scope_subnet(start: IP, end: IP, netmask: IP | None) -> Network:
    if netmask is not None:
        return ip_network(f"{start}/{netmask}", strict=False)
    # Unset netmask means dnsmasq takes it from the interface, which the API doesn't
    # expose. Assume the common /24 if the range fits in one; otherwise the smallest
    # network that covers the range.
    guess = ip_network(f"{start}/24", strict=False)
    if end in guess:
        return guess
    prefix = 24
    while end not in guess and prefix > 0:
        prefix -= 1
        guess = ip_network(f"{start}/{prefix}", strict=False)
    return guess


def _add_lease(server: str, lease: dict[str, Any], subnet: Network | None, model: LabModel) -> None:
    ip = _ip_or_none(lease.get("ip"))
    if ip is None:
        return
    hostname = (lease.get("name") or "").strip()
    mac = (lease.get("hwaddr") or "").lower()
    if not hostname or hostname == "*":  # dnsmasq uses "*" when the client sent no name
        hostname = f"dhcp-{mac.replace(':', '')}" if mac else f"dhcp-{ip}"
    if hostname == server or model.device(hostname) is not None:
        return
    prefix = subnet.prefixlen if subnet is not None and ip in subnet else ip.max_prefixlen
    model.devices.append(Device(name=hostname, kind=DeviceKind.CLIENT, tags=["dhcp-lease"]))
    model.addresses.append(
        Address(device=hostname, address=ip_interface(f"{ip}/{prefix}"), dhcp=True)
    )
