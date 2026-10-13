"""Network discovery from the machine LabWarden runs on.

Finds hosts that no other collector knows about:

* **ARP table**: IP-to-MAC pairs the machine has already seen on its own LAN
  segment. It's read from ``/proc/net/arp`` on Linux, or with ``arp -a``
  (Windows) and ``arp -an`` (macOS).
* **Ping sweep** of the configured IPv4 subnets: one echo request per address,
  rate-limited (``rate`` per second) and capped at ``max_hosts`` addresses.
  Hosts on other VLANs answer only if the firewall allows ICMP from here.
* **Reverse DNS** for each live host, to give it a readable name.
* **nmap service scan**: opt-in (``nmap: true``), TCP connect scan of the top
  ``nmap_top_ports`` ports on live hosts only. Needs nmap installed. Only scan
  networks you own.

None of this changes anything on the targets. All local commands are argv
lists checked by ``ALLOWLIST``, and no shell is involved.

When LabWarden runs in Docker, discovery needs ``network_mode: host``.
Otherwise it sweeps from inside the container's bridge network and its ARP
table is the container's own.

Config::

    - name: discovery
      plugin: discovery
      options:
        subnets: [192.168.10.0/24, 192.168.20.0/24]
        exclude: [192.168.20.1]
        # nmap: true
"""

from __future__ import annotations

import logging
import re
import socket
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_interface
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, model_validator

from labwarden.collectors.allowlist import CommandAllowlist
from labwarden.collectors.base import Collector
from labwarden.model.entities import Address, Device, DeviceKind, Interface, Service
from labwarden.model.lab import LabModel

log = logging.getLogger(__name__)

#: Absolute ceiling on addresses per run, whatever ``max_hosts`` says.
HARD_MAX_HOSTS = 4096

_IPV4 = r"re:(?:\d{1,3}\.){3}\d{1,3}"
_INT = r"re:\d{1,5}"
ALLOWLIST = CommandAllowlist(
    [
        ("ping", "-c", "1", "-W", _INT, "-n", _IPV4),  # Linux (iputils, busybox)
        ("ping", "-c", "1", "-t", _INT, "-n", _IPV4),  # macOS
        ("ping", "-n", "1", "-w", _INT, _IPV4),  # Windows
        ("arp", "-a"),  # Windows
        ("arp", "-an"),  # macOS
        (
            "nmap",
            "-sT",
            "-sV",
            "-Pn",
            "--top-ports",
            _INT,
            "-T3",
            "--host-timeout",
            r"re:\d{1,4}s",
            "-oX",
            "-",
            _IPV4,
        ),
    ]
)

#: (exit status, stdout, stderr)
CommandResult = tuple[int, str, str]
Runner = Callable[[Sequence[str]], CommandResult]

#: Interface name used for MACs seen in the ARP table; the remote NIC's real name is unknown.
OBSERVED_IFACE = "observed"


class DiscoveryOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subnets: list[IPv4Network] = Field(min_length=1)
    exclude: list[IPv4Address] = Field(default_factory=list)
    max_hosts: int = Field(default=1024, ge=1, le=HARD_MAX_HOSTS)
    ping: bool = True
    ping_timeout: float = Field(default=1.0, gt=0, le=10)
    #: Pings started per second.
    rate: float = Field(default=50.0, gt=0, le=500)
    concurrency: int = Field(default=32, ge=1, le=128)
    arp: bool = True
    resolve_names: bool = True
    nmap: bool = False
    nmap_top_ports: int = Field(default=100, ge=1, le=1000)
    nmap_host_timeout_s: int = Field(default=120, ge=10, le=3600)

    @model_validator(mode="after")
    def _bounded(self) -> DiscoveryOptions:
        total = sum(max(n.num_addresses - 2, 1) for n in self.subnets)
        if total > self.max_hosts:
            raise ValueError(
                f"subnets cover {total} addresses, more than max_hosts={self.max_hosts}. "
                "Narrow the subnets or raise max_hosts."
            )
        return self


class DiscoveryCollector(Collector):
    plugin = "discovery"
    description = "ARP table, rate-limited ping sweep, reverse DNS and opt-in nmap service scan."
    provides = frozenset({"devices", "interfaces", "addresses", "services"})
    Options = DiscoveryOptions

    # Seams for tests.
    _runner: Runner | None = None
    _platform: str = sys.platform
    _sleep: Callable[[float], None] = staticmethod(time.sleep)
    _reverse_dns: Callable[[str], str | None] | None = None
    _proc_arp: Path = Path("/proc/net/arp")

    def collect(self) -> LabModel:
        opts: DiscoveryOptions = self.options
        run = self._runner or _run_local
        targets = _targets(opts)

        live = set(self._sweep(run, targets)) if opts.ping else set()
        # Read ARP after the sweep: the pings are what fill it for this segment.
        # Hosts that drop ICMP still answer ARP, so they show up here too.
        macs = self._read_arp(run) if opts.arp else {}
        wanted = set(targets)
        in_scope = {ip: mac for ip, mac in macs.items() if ip in wanted}
        live |= set(in_scope)

        resolve = self._reverse_dns or _lookup_ptr
        names = {ip: resolve(str(ip)) for ip in live} if opts.resolve_names else {}

        services: dict[IPv4Address, list[tuple[str, int, str | None]]] = {}
        if opts.nmap:
            for ip in sorted(live):
                services[ip] = self._nmap(run, ip)

        return build_model(
            subnets=opts.subnets, live=live, macs=in_scope, names=names, services=services
        )

    def _read_arp(self, run: Runner) -> dict[IPv4Address, str]:
        if self._platform.startswith("linux"):
            try:
                return parse_proc_arp(self._proc_arp.read_text(encoding="utf-8"))
            except OSError as exc:
                log.warning("%s: can't read %s: %s", self.target, self._proc_arp, exc)
                return {}
        argv = ["arp", "-a"] if self._platform == "win32" else ["arp", "-an"]
        code, out, err = _checked(run, argv)
        if code != 0:
            log.warning("%s: %s failed: %s", self.target, " ".join(argv), err.strip()[:200])
            return {}
        return parse_arp_output(out)

    def _sweep(self, run: Runner, targets: list[IPv4Address]) -> list[IPv4Address]:
        opts: DiscoveryOptions = self.options
        interval = 1.0 / opts.rate
        lock = threading.Lock()
        alive: list[IPv4Address] = []

        def probe(ip: IPv4Address) -> None:
            argv = ping_argv(self._platform, ip, opts.ping_timeout)
            code, out, _ = _checked(run, argv)
            if is_ping_reply(code, out):
                with lock:
                    alive.append(ip)

        with ThreadPoolExecutor(max_workers=opts.concurrency) as pool:
            for ip in targets:
                pool.submit(probe, ip)
                self._sleep(interval)
        return sorted(alive)

    def _nmap(self, run: Runner, ip: IPv4Address) -> list[tuple[str, int, str | None]]:
        opts: DiscoveryOptions = self.options
        argv = [
            "nmap", "-sT", "-sV", "-Pn",
            "--top-ports", str(opts.nmap_top_ports),
            "-T3", "--host-timeout", f"{opts.nmap_host_timeout_s}s",
            "-oX", "-", str(ip),
        ]  # fmt: skip
        code, out, err = _checked(run, argv)
        if code != 0:
            log.warning("%s: nmap %s failed: %s", self.target, ip, err.strip()[:200])
            return []
        return parse_nmap_xml(out).get(ip, [])


def _checked(run: Runner, argv: Sequence[str]) -> CommandResult:
    ALLOWLIST.check(argv)
    return run(argv)


def _run_local(argv: Sequence[str]) -> CommandResult:
    ALLOWLIST.check(argv)  # the last check before anything runs
    try:
        proc = subprocess.run(
            list(argv), capture_output=True, text=True, timeout=600, check=False, shell=False
        )
    except FileNotFoundError:
        return 127, "", f"{argv[0]}: command not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"{argv[0]}: timed out"
    return proc.returncode, proc.stdout, proc.stderr


def _lookup_ptr(ip: str) -> str | None:
    try:
        name = socket.gethostbyaddr(ip)[0]
    except OSError:
        return None
    return name.rstrip(".") or None


def _targets(opts: DiscoveryOptions) -> list[IPv4Address]:
    excluded = set(opts.exclude)
    seen: set[IPv4Address] = set()
    targets = []
    for net in opts.subnets:
        hosts = list(net.hosts()) or [net.network_address]
        for ip in hosts:
            if ip not in excluded and ip not in seen:
                seen.add(ip)
                targets.append(ip)
    return targets


# --- pure helpers, tested directly ----------------------------------------------------------


def ping_argv(platform: str, ip: IPv4Address, timeout: float) -> list[str]:
    seconds = str(max(1, round(timeout)))
    if platform == "win32":
        return ["ping", "-n", "1", "-w", str(int(timeout * 1000)), str(ip)]
    if platform == "darwin":
        return ["ping", "-c", "1", "-t", seconds, "-n", str(ip)]
    return ["ping", "-c", "1", "-W", seconds, "-n", str(ip)]


def is_ping_reply(code: int, output: str) -> bool:
    """True only for a real echo reply.

    Windows ping exits 0 even for "Destination host unreachable" sent by a
    router, so also require the TTL that only an echo reply prints.
    """
    return code == 0 and "ttl=" in output.lower()


def _mac(raw: str) -> str | None:
    mac = raw.strip().lower().replace("-", ":")
    if not re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
        return None
    if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") or mac.startswith("01:00:5e"):
        return None  # incomplete, broadcast, IPv4 multicast
    return mac


def _v4(raw: str) -> IPv4Address | None:
    try:
        ip = ip_address(raw)
    except ValueError:
        return None
    return ip if isinstance(ip, IPv4Address) and not ip.is_multicast else None


def parse_proc_arp(text: str) -> dict[IPv4Address, str]:
    """``/proc/net/arp``: IP, HW type, Flags, HW address, Mask, Device."""
    found = {}
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4 or fields[2] == "0x0":  # 0x0 = incomplete entry
            continue
        ip, mac = _v4(fields[0]), _mac(fields[3])
        if ip and mac:
            found[ip] = mac
    return found


_ARP_WINDOWS = re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+\w+", re.MULTILINE)
_ARP_BSD = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)")


def parse_arp_output(text: str) -> dict[IPv4Address, str]:
    """``arp -a`` (Windows) or ``arp -an`` (macOS)."""
    found = {}
    for regex in (_ARP_WINDOWS, _ARP_BSD):
        for raw_ip, raw_mac in regex.findall(text):
            # macOS drops leading zeros (a:b:c:...); pad each octet back to two digits.
            octets = re.split("[:-]", raw_mac)
            ip, mac = _v4(raw_ip), _mac(":".join(o.zfill(2) for o in octets))
            if ip and mac:
                found[ip] = mac
    return found


def parse_nmap_xml(xml: str) -> dict[IPv4Address, list[tuple[str, int, str | None]]]:
    """Open ports per host from ``nmap -oX -``: (protocol, port, service description)."""
    result: dict[IPv4Address, list[tuple[str, int, str | None]]] = {}
    root = ET.fromstring(xml)
    for host in root.iter("host"):
        addr = host.find("address[@addrtype='ipv4']")
        ip = _v4(addr.get("addr", "")) if addr is not None else None
        if ip is None:
            continue
        ports = []
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            proto = port.get("protocol")
            if proto not in ("tcp", "udp"):
                continue
            svc = port.find("service")
            desc = None
            if svc is not None:
                parts = [svc.get("name"), svc.get("product"), svc.get("version")]
                desc = " ".join(p for p in parts if p) or None
            ports.append((proto, int(port.get("portid", "0")), desc))
        result[ip] = ports
    return result


def build_model(
    *,
    subnets: Sequence[IPv4Network],
    live: set[IPv4Address],
    macs: dict[IPv4Address, str],
    names: dict[IPv4Address, str | None],
    services: dict[IPv4Address, list[tuple[str, int, str | None]]],
) -> LabModel:
    model = LabModel()
    used: set[str] = set()
    for ip in sorted(live):
        name = names.get(ip) or f"host-{str(ip).replace('.', '-')}"
        if name in used:  # two IPs with the same PTR name
            name = f"{name}-{str(ip).replace('.', '-')}"
        used.add(name)
        net = next((n for n in subnets if ip in n), None)
        prefix = net.prefixlen if net is not None else 32
        mac = macs.get(ip)
        model.devices.append(
            Device(name=name, kind=DeviceKind.OTHER, management_ip=ip, tags=["discovered"])
        )
        if mac:
            model.interfaces.append(Interface(device=name, name=OBSERVED_IFACE, mac=mac))
        model.addresses.append(
            Address(
                device=name,
                interface=OBSERVED_IFACE if mac else None,
                address=ip_interface(f"{ip}/{prefix}"),
            )
        )
        for proto, port, desc in services.get(ip, []):
            model.services.append(
                Service(device=name, address=ip, port=port, protocol=proto, process=desc)
            )
    return model
