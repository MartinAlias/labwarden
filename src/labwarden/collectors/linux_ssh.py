"""Linux hosts over SSH, running a fixed set of read-only commands.

Every command is a constant argv in ``COMMANDS`` and is checked against
``ALLOWLIST`` right before it is sent. There is no way to pass in a command
from config or from the agent. On the remote host the ``labwarden`` user's
``authorized_keys`` entry forces ``deploy/ssh/labwarden-ssh-wrapper.sh``, which
runs only these exact command lines. ``tests/test_linux_ssh.py`` checks that
the two lists stay identical. See ``deploy/ssh/README.md`` for the setup.

What it reads:

* ``ip -d -j addr``: interfaces (MAC, MTU, state, VLAN ID) and addresses.
* ``ip -j route`` / ``ip -j -6 route``: the main routing table.
* ``ss -H -tulpn``: listening TCP/UDP sockets. Process names of other users'
  sockets are only visible to root, so some may be blank.
* ``cat /etc/os-release``: distribution name, used as the device's ``os``.
* ``cat /etc/resolv.conf`` and ``resolvectl dns``: the DNS servers the host
  uses, recorded as ``dns-server:<ip>`` device tags.
* ``sudo -n nft -j list ruleset``: opt-in (``nftables: true``), and needs a
  sudoers entry. Parsed minimally here; the full parser is Phase 2.

Host keys must already be in ``known_hosts``. Unknown hosts are rejected,
never auto-trusted.

Config::

    - name: docker-server-host
      plugin: linux_ssh
      options:
        host: 192.168.20.10
        user: labwarden
        key_file: ~/.ssh/labwarden_ed25519
        # known_hosts: ~/.ssh/known_hosts   # default: the system known_hosts
        # nftables: true                    # needs the sudoers line in deploy/ssh
"""

from __future__ import annotations

import json
import logging
import re
import shlex
from collections.abc import Callable, Sequence
from ipaddress import ip_address, ip_interface, ip_network
from pathlib import Path
from typing import Any

import paramiko
from pydantic import BaseModel, ConfigDict, SecretStr

from labwarden.collectors.allowlist import CommandAllowlist
from labwarden.collectors.base import Collector, ReadOnlyViolation
from labwarden.model.entities import (
    Address,
    Device,
    DeviceKind,
    FirewallRule,
    Interface,
    Route,
    Service,
)
from labwarden.model.lab import LabModel

log = logging.getLogger(__name__)

#: Every command this collector can run. Keep in sync with the SSH wrapper.
COMMANDS: dict[str, tuple[str, ...]] = {
    "addr": ("ip", "-d", "-j", "addr"),
    "route4": ("ip", "-j", "route"),
    "route6": ("ip", "-j", "-6", "route"),
    "sockets": ("ss", "-H", "-tulpn"),
    "os": ("cat", "/etc/os-release"),
    "resolv": ("cat", "/etc/resolv.conf"),
    "resolvectl": ("resolvectl", "dns"),
    "nft": ("sudo", "-n", "nft", "-j", "list", "ruleset"),
}
ALLOWLIST = CommandAllowlist(COMMANDS.values())

#: Cap on one command's output, so a misbehaving host can't exhaust memory.
MAX_OUTPUT_BYTES = 8 * 1024 * 1024

#: (exit status, stdout, stderr)
CommandResult = tuple[int, str, str]
Runner = Callable[[Sequence[str]], CommandResult]


class LinuxSshOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str
    port: int = 22
    user: str = "labwarden"
    key_file: Path
    key_passphrase: SecretStr | None = None
    #: known_hosts file to trust. Default: the system's ``~/.ssh/known_hosts``.
    known_hosts: Path | None = None
    timeout: float = 15.0
    #: Also read the nftables ruleset (needs the sudoers entry from deploy/ssh).
    nftables: bool = False
    #: Name of the host in the Lab Model. Defaults to the target name.
    device_name: str | None = None


class SshCommandError(Exception):
    """A required command failed on the remote host."""


class SshSession:
    """One SSH connection that will only run commands its allowlist accepts.

    Probes reuse this with their own allowlist (``labwarden.probes``).
    """

    def __init__(
        self, opts: LinuxSshOptions, base_dir: Path, allowlist: CommandAllowlist = ALLOWLIST
    ) -> None:
        self._opts = opts
        self._base_dir = base_dir
        self._allowlist = allowlist
        self._client: paramiko.SSHClient | None = None

    def _path(self, path: Path) -> Path:
        path = path.expanduser()
        return path if path.is_absolute() else self._base_dir / path

    def __enter__(self) -> SshSession:
        opts = self._opts
        client = paramiko.SSHClient()
        if opts.known_hosts is not None:
            client.load_host_keys(str(self._path(opts.known_hosts)))
        else:
            client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            client.connect(
                opts.host,
                port=opts.port,
                username=opts.user,
                key_filename=str(self._path(opts.key_file)),
                passphrase=(
                    opts.key_passphrase.get_secret_value() if opts.key_passphrase else None
                ),
                timeout=opts.timeout,
                banner_timeout=opts.timeout,
                auth_timeout=opts.timeout,
                allow_agent=False,
                look_for_keys=False,
            )
        except paramiko.SSHException as exc:
            client.close()
            if "not found in known_hosts" in str(exc):
                raise SshCommandError(
                    f"{opts.host} is not in known_hosts. Connect once with ssh and verify "
                    "the fingerprint, or set options.known_hosts."
                ) from exc
            raise
        self._client = client
        return self

    def __exit__(self, *exc: object) -> None:
        if self._client is not None:
            self._client.close()

    def run(self, argv: Sequence[str]) -> CommandResult:
        self._allowlist.check(argv)  # the last check before anything leaves the process
        command = " ".join(argv)
        if shlex.join(argv) != command:
            # The remote wrapper splits on plain spaces and never un-quotes, so an
            # argument that needs quoting could never mean the same thing there.
            raise ReadOnlyViolation(f"argument needs shell quoting: {list(argv)!r}")
        assert self._client is not None
        stdin, stdout, stderr = self._client.exec_command(command, timeout=self._opts.timeout)
        stdin.close()
        out = stdout.read(MAX_OUTPUT_BYTES).decode("utf-8", "replace")
        err = stderr.read(64 * 1024).decode("utf-8", "replace")
        return stdout.channel.recv_exit_status(), out, err


class LinuxSshCollector(Collector):
    plugin = "linux_ssh"
    description = (
        "Linux hosts over SSH: interfaces, addresses, routes, listening sockets, nftables."
    )
    provides = frozenset(
        {"devices", "interfaces", "addresses", "routes", "services", "firewall_rules"}
    )
    Options = LinuxSshOptions

    #: Tests swap in a fake runner instead of a real SSH session.
    _runner: Runner | None = None

    def collect(self) -> LabModel:
        if self._runner is not None:
            return self._collect_with(self._runner)
        with SshSession(self.options, self.base_dir) as session:
            return self._collect_with(session.run)

    def _collect_with(self, run: Runner) -> LabModel:
        opts: LinuxSshOptions = self.options

        def required(key: str) -> str:
            argv = COMMANDS[key]
            ALLOWLIST.check(argv)
            code, out, err = run(argv)
            if code != 0:
                raise SshCommandError(f"{shlex.join(argv)!r} exited {code}: {err.strip()[:200]}")
            return out

        def optional(key: str, *, quiet: bool = False) -> str | None:
            try:
                return required(key)
            except SshCommandError as exc:
                (log.debug if quiet else log.warning)("%s: %s; skipping", self.target, exc)
                return None

        outputs = {
            "addr": required("addr"),
            "route4": required("route4"),
            "route6": optional("route6", quiet=True),
            "sockets": required("sockets"),
            "os": optional("os"),
            "resolv": optional("resolv"),
            "resolvectl": optional("resolvectl", quiet=True),
            "nft": optional("nft") if opts.nftables else None,
        }
        return parse_linux(
            name=opts.device_name or self.target,
            management_host=opts.host,
            **outputs,
        )


# --- parsing (pure functions, tested against recorded output) ------------------------------


def parse_linux(
    *,
    name: str,
    management_host: str | None,
    addr: str,
    route4: str,
    sockets: str,
    route6: str | None = None,
    os: str | None = None,
    resolv: str | None = None,
    resolvectl: str | None = None,
    nft: str | None = None,
) -> LabModel:
    model = LabModel()
    try:
        management_ip = ip_address(management_host) if management_host else None
    except ValueError:
        management_ip = None
    model.devices.append(
        Device(
            name=name,
            kind=DeviceKind.SERVER,
            os=_parse_os_release(os) if os else None,
            management_ip=management_ip,
            tags=[f"dns-server:{s}" for s in _dns_servers(resolv, resolvectl)],
        )
    )
    interfaces, addresses = _parse_ip_addr(name, json.loads(addr))
    model.interfaces.extend(interfaces)
    model.addresses.extend(addresses)
    model.routes.extend(_parse_routes(name, json.loads(route4), v6=False))
    if route6:
        model.routes.extend(_parse_routes(name, json.loads(route6), v6=True))
    model.services.extend(_parse_ss(name, sockets))
    if nft:
        model.firewall_rules.extend(parse_nft(name, json.loads(nft)))
    return model


def _parse_os_release(text: str) -> str | None:
    values = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value.strip().strip("\"'")
    return values.get("PRETTY_NAME") or values.get("NAME")


_STUB_RESOLVERS = {"127.0.0.53", "127.0.0.54"}


def _dns_servers(resolv: str | None, resolvectl: str | None) -> list[str]:
    """Upstream DNS servers. resolvectl's view wins over the systemd-resolved stub."""
    found: list[str] = []
    if resolvectl:
        for line in resolvectl.splitlines():
            _, _, rest = line.partition(": ")
            found.extend(rest.split())
    if not found and resolv:
        for line in resolv.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                found.append(parts[1])
    servers = []
    for token in found:
        try:
            ip = str(ip_address(token.split("#")[0].split("%")[0]))
        except ValueError:
            continue
        if ip not in servers and not (resolvectl and ip in _STUB_RESOLVERS):
            servers.append(ip)
    return servers


#: veth pairs come and go with every container restart; tracking them is pure diff noise.
_SKIP_IFACES = re.compile(r"^(lo|veth[0-9a-f]+)$")


def _parse_ip_addr(device: str, links: list[dict[str, Any]]) -> tuple[list, list]:
    interfaces: list[Interface] = []
    addresses: list[Address] = []
    for link in links:
        ifname = link.get("ifname", "")
        if not ifname or _SKIP_IFACES.match(ifname):
            continue
        linkinfo = link.get("linkinfo") or {}
        vlan_id = None
        if linkinfo.get("info_kind") == "vlan":
            vlan_id = (linkinfo.get("info_data") or {}).get("id")
        interfaces.append(
            Interface(
                device=device,
                name=ifname,
                mac=link.get("address") if link.get("link_type") == "ether" else None,
                state=_link_state(link),
                mtu=link.get("mtu"),
                vlan_id=vlan_id,
            )
        )
        for info in link.get("addr_info") or []:
            family = info.get("family")
            if info.get("scope") == "host" or (family == "inet6" and info.get("scope") == "link"):
                continue
            if family not in ("inet", "inet6") or "local" not in info:
                continue
            addresses.append(
                Address(
                    device=device,
                    interface=ifname,
                    address=ip_interface(f"{info['local']}/{info.get('prefixlen', 32)}"),
                    dhcp=bool(info.get("dynamic")) if family == "inet" else None,
                )
            )
    return interfaces, addresses


def _link_state(link: dict[str, Any]) -> str:
    operstate = str(link.get("operstate", "")).lower()
    if operstate in ("up", "down"):
        return operstate
    # Tunnels and some virtual links report UNKNOWN even when they work.
    return "up" if "LOWER_UP" in (link.get("flags") or []) else "unknown"


def _parse_routes(device: str, routes: list[dict[str, Any]], *, v6: bool) -> list[Route]:
    result: list[Route] = []
    seen: set[tuple[str, ...]] = set()
    for r in routes:
        if r.get("type", "unicast") != "unicast":
            continue  # multicast, unreachable, blackhole, ...
        dst = r.get("dst", "")
        dst = ("::/0" if v6 else "0.0.0.0/0") if dst == "default" else dst
        try:
            route = Route(
                device=device,
                destination=ip_network(dst, strict=False),
                gateway=r.get("gateway"),
                interface=r.get("dev"),
                metric=r.get("metric"),
            )
        except ValueError:
            log.debug("skipping unparseable route %r", r)
            continue
        if route.key() not in seen:
            seen.add(route.key())
            result.append(route)
    return result


_PROCESS = re.compile(r'users:\(\("([^"]+)"')


def _parse_ss(device: str, text: str) -> list[Service]:
    """Parse ``ss -H -tulpn``: Netid State Recv-Q Send-Q Local Peer [Process]."""
    services: list[Service] = []
    seen: set[tuple[str, ...]] = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 6 or fields[0] not in ("tcp", "udp"):
            continue
        host, _, port = fields[4].rpartition(":")
        if not port.isdigit():
            continue
        host = host.strip("[]").split("%")[0]
        address = "::" if host == "*" else host  # "*" is a dual-stack wildcard
        match = _PROCESS.search(" ".join(fields[6:]))
        try:
            service = Service(
                device=device,
                address=address,
                port=int(port),
                protocol=fields[0],
                process=match.group(1) if match else None,
            )
        except ValueError:
            log.debug("skipping unparseable socket line %r", line)
            continue
        if service.key() not in seen:
            seen.add(service.key())
            services.append(service)
    return services


# --- nftables (minimal; the full parser and simulator are Phase 2) -------------------------

_VERDICTS = {"accept": "allow", "drop": "block", "reject": "reject"}
_HOOK_DIRECTION = {"input": "in", "output": "out"}


def parse_nft(device: str, ruleset: dict[str, Any]) -> list[FirewallRule]:
    """Filter-chain rules with a verdict, plus each base chain's default policy.

    Rules without a final verdict (jumps, counters, logging) are skipped, and so
    are NAT chains. Match expressions this parser doesn't understand end up in
    the rule's description, so nothing is silently misrepresented as "any".
    """
    chains: dict[str, dict[str, Any]] = {}
    rules: dict[str, list[dict[str, Any]]] = {}
    for item in ruleset.get("nftables", []):
        if "chain" in item:
            c = item["chain"]
            if c.get("type", "filter") == "filter":
                key = f"{c['family']} {c['table']} {c['name']}"
                chains[key] = c
                rules.setdefault(key, [])
        elif "rule" in item:
            r = item["rule"]
            rules.setdefault(f"{r['family']} {r['table']} {r['chain']}", []).append(r)

    result: list[FirewallRule] = []
    for key, chain in chains.items():
        direction = _HOOK_DIRECTION.get(chain.get("hook", ""), "any")
        order = 0
        for rule in rules.get(key, []):
            parsed = _nft_rule(device, key, order, direction, rule)
            if parsed is not None:
                result.append(parsed)
                order += 1
        policy = chain.get("policy")
        if chain.get("hook") and policy in _VERDICTS:
            result.append(
                FirewallRule(
                    device=device,
                    chain=key,
                    order=order,
                    action=_VERDICTS[policy],
                    direction=direction,
                    description="default policy",
                )
            )
    return result


def _nft_rule(
    device: str, chain: str, order: int, direction: str, rule: dict[str, Any]
) -> FirewallRule | None:
    exprs = rule.get("expr") or []
    verdict = next((_VERDICTS[k] for e in exprs for k in e if k in _VERDICTS), None)
    if verdict is None:
        return None
    fields: dict[str, Any] = {}
    notes: list[str] = []
    for e in exprs:
        match = e.get("match")
        if match is None:
            continue
        left, right, op = match.get("left") or {}, match.get("right"), match.get("op", "==")
        payload = left.get("payload") or {}
        meta_key = (left.get("meta") or {}).get("key")
        value = _nft_value(right)
        if op == "==" and payload.get("field") in ("dport", "sport"):
            fields["protocol"] = payload.get("protocol", "any")
            fields["dst_port" if payload["field"] == "dport" else "src_port"] = value
        elif op == "==" and payload.get("field") in ("saddr", "daddr"):
            fields["src" if payload["field"] == "saddr" else "dst"] = value
        elif op == "==" and meta_key == "l4proto" and value in ("tcp", "udp", "icmp"):
            fields["protocol"] = value
        elif op == "==" and payload.get("protocol") in ("icmp", "icmpv6"):
            fields["protocol"] = "icmp"
            notes.append(f"{payload['protocol']} {payload.get('field')} {value}")
        else:
            notes.append(f"{_nft_left(left)} {op} {value}")
    if rule.get("comment"):
        notes.insert(0, str(rule["comment"]))
    protocol = fields.pop("protocol", "any")
    return FirewallRule(
        device=device,
        chain=chain,
        order=order,
        action=verdict,
        direction=direction,
        protocol=protocol if protocol in ("tcp", "udp", "icmp") else "any",
        description="; ".join(notes) or None,
        **fields,
    )


def _nft_left(left: dict[str, Any]) -> str:
    if "payload" in left:
        return f"{left['payload'].get('protocol')} {left['payload'].get('field')}"
    for kind in ("meta", "ct"):
        if kind in left:
            return f"{kind} {left[kind].get('key')}"
    return json.dumps(left, sort_keys=True)


def _nft_value(right: Any) -> str:
    if isinstance(right, dict):
        if "prefix" in right:
            return f"{right['prefix']['addr']}/{right['prefix']['len']}"
        if "set" in right:
            return ",".join(_nft_value(v) for v in right["set"])
        if "range" in right:
            return "-".join(_nft_value(v) for v in right["range"])
        return json.dumps(right, sort_keys=True)
    if isinstance(right, list):
        return ",".join(_nft_value(v) for v in right)
    return str(right)
