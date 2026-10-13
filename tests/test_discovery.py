from __future__ import annotations

import logging
import threading
from collections.abc import Sequence
from ipaddress import IPv4Address, ip_interface
from pathlib import Path

import pytest
from pydantic import ValidationError

from labwarden.collectors import ReadOnlyViolation
from labwarden.collectors.discovery import (
    ALLOWLIST,
    DiscoveryCollector,
    DiscoveryOptions,
    _run_local,
    is_ping_reply,
    parse_arp_output,
    parse_nmap_xml,
    parse_proc_arp,
    ping_argv,
)

FIXTURES = Path(__file__).parent / "fixtures" / "discovery"
LINUX_REPLY = "64 bytes from 192.168.4.1: icmp_seq=1 ttl=64 time=0.412 ms\n"
EMPTY_NMAP = (
    '<?xml version="1.0"?><nmaprun><host>'
    '<address addr="{ip}" addrtype="ipv4"/><ports/></host></nmaprun>'
)


def ip(s: str) -> IPv4Address:
    return IPv4Address(s)


class FakeNetwork:
    """Answers ping/nmap like a small LAN; records every command."""

    def __init__(self, answering: set[str], nmap_installed: bool = True) -> None:
        self.answering = answering
        self.nmap_installed = nmap_installed
        self.calls: list[list[str]] = []
        self._lock = threading.Lock()

    def __call__(self, argv: Sequence[str]) -> tuple[int, str, str]:
        assert ALLOWLIST.is_allowed(argv), argv
        with self._lock:
            self.calls.append(list(argv))
        target = argv[-1]
        if argv[0] == "ping":
            if target in self.answering:
                return 0, LINUX_REPLY, ""
            return 1, "", ""
        if argv[0] == "nmap":
            if not self.nmap_installed:
                return 127, "", "nmap: command not found"
            if target == "192.168.4.2":
                return 0, (FIXTURES / "nmap_pihole.xml").read_text(encoding="utf-8"), ""
            return 0, EMPTY_NMAP.format(ip=target), ""
        raise AssertionError(f"unexpected command {argv}")


PTR = {"192.168.4.1": "router.lan", "192.168.4.2": "pihole.lan"}


def _collector(fake: FakeNetwork, **options: object) -> tuple[DiscoveryCollector, list[float]]:
    opts = DiscoveryOptions.model_validate(
        {"subnets": ["192.168.4.0/24"], "exclude": ["192.168.4.254"], **options}
    )
    c = DiscoveryCollector("discovery", opts, Path("."))
    sleeps: list[float] = []
    c._runner = fake
    c._platform = "linux"
    c._sleep = sleeps.append
    c._reverse_dns = PTR.get
    c._proc_arp = FIXTURES / "proc_arp.txt"
    return c, sleeps


def test_sweep_arp_and_names() -> None:
    fake = FakeNetwork(answering={"192.168.4.1", "192.168.4.2", "192.168.4.67"})
    model = _collector(fake)[0].collect()

    names = [d.name for d in model.devices]
    # .50 never answered ping but is in the ARP table (drops ICMP); .99 is incomplete,
    # 192.168.99.5 is outside the configured subnets.
    assert names == ["router.lan", "pihole.lan", "host-192-168-4-50", "host-192-168-4-67"]
    assert all(d.tags == ["discovered"] for d in model.devices)
    assert model.device("pihole.lan").management_ip == ip("192.168.4.2")

    macs = {i.device: i.mac for i in model.interfaces}
    assert macs["host-192-168-4-50"] == "02:00:00:00:04:32"
    addrs = {a.device: a.address for a in model.addresses}
    assert addrs["router.lan"] == ip_interface("192.168.4.1/24")
    assert model.services == []  # nmap is opt-in


def test_sweep_is_bounded_and_rate_limited() -> None:
    fake = FakeNetwork(answering=set())
    collector, sleeps = _collector(fake, rate=20)
    collector.collect()
    pinged = [argv[-1] for argv in fake.calls if argv[0] == "ping"]
    assert len(pinged) == 253  # 254 usable addresses minus the excluded .254
    assert "192.168.4.254" not in pinged
    assert "192.168.4.0" not in pinged and "192.168.4.255" not in pinged
    assert len(sleeps) == 253 and set(sleeps) == {1 / 20}


def test_ping_and_arp_can_be_disabled() -> None:
    fake = FakeNetwork(answering={"192.168.4.1"})
    model = _collector(fake, ping=False)[0].collect()
    assert not any(argv[0] == "ping" for argv in fake.calls)
    assert len(model.devices) == 4  # from ARP alone

    model = _collector(fake, arp=False)[0].collect()
    assert [d.name for d in model.devices] == ["router.lan"]
    assert model.interfaces == []


def test_nmap_services_are_opt_in() -> None:
    fake = FakeNetwork(answering={"192.168.4.1", "192.168.4.2"})
    model = _collector(fake, nmap=True, resolve_names=False)[0].collect()
    scanned = [argv[-1] for argv in fake.calls if argv[0] == "nmap"]
    assert sorted(scanned) == ["192.168.4.1", "192.168.4.2", "192.168.4.50", "192.168.4.67"]
    services = {(s.device, s.port, s.process) for s in model.services}
    assert services == {
        ("host-192-168-4-2", 22, "ssh OpenSSH 9.2p1 Debian 2+deb12u3"),
        ("host-192-168-4-2", 53, "domain dnsmasq pi-hole-v2.90+1"),
        ("host-192-168-4-2", 80, "http"),
    }  # 443 is filtered, not open


def test_missing_nmap_is_a_warning(caplog: pytest.LogCaptureFixture) -> None:
    fake = FakeNetwork(answering={"192.168.4.2"}, nmap_installed=False)
    with caplog.at_level(logging.WARNING):
        model = _collector(fake, nmap=True)[0].collect()
    assert model.services == [] and len(model.devices) == 4
    assert "nmap" in caplog.text


def test_duplicate_ptr_names_stay_unique() -> None:
    fake = FakeNetwork(answering={"192.168.4.1", "192.168.4.2"})
    collector, _ = _collector(fake, arp=False)
    collector._reverse_dns = lambda _ip: "same.lan"
    names = [d.name for d in collector.collect().devices]
    assert names == ["same.lan", "same.lan-192-168-4-2"]


@pytest.mark.parametrize("platform", ["win32", "darwin"])
def test_non_linux_reads_arp_with_the_arp_command(platform: str) -> None:
    fixture = "arp_windows.txt" if platform == "win32" else "arp_macos.txt"

    def run(argv: Sequence[str]) -> tuple[int, str, str]:
        assert ALLOWLIST.is_allowed(argv), argv
        if argv[0] == "arp":
            return 0, (FIXTURES / fixture).read_text(encoding="utf-8"), ""
        return 1, "", ""

    collector, _ = _collector(FakeNetwork(set()))
    collector._runner = run
    collector._platform = platform
    model = collector.collect()
    assert [d.name for d in model.devices] == ["router.lan", "pihole.lan"]


# --- parsers and argv ---------------------------------------------------------------------


def test_parse_proc_arp() -> None:
    found = parse_proc_arp((FIXTURES / "proc_arp.txt").read_text(encoding="utf-8"))
    assert ip("192.168.4.99") not in found  # incomplete
    assert found[ip("192.168.99.5")] == "02:00:00:00:99:05"


def test_parse_windows_arp_skips_broadcast_and_multicast() -> None:
    found = parse_arp_output((FIXTURES / "arp_windows.txt").read_text(encoding="utf-8"))
    assert found == {ip("192.168.4.1"): "02:00:00:00:04:01", ip("192.168.4.2"): "02:00:00:00:04:02"}


def test_parse_macos_arp_pads_octets() -> None:
    found = parse_arp_output((FIXTURES / "arp_macos.txt").read_text(encoding="utf-8"))
    assert found == {ip("192.168.4.1"): "02:00:00:00:04:01", ip("192.168.4.2"): "02:00:00:00:04:02"}


def test_parse_nmap_xml() -> None:
    result = parse_nmap_xml((FIXTURES / "nmap_pihole.xml").read_text(encoding="utf-8"))
    assert [p for _, p, _ in result[ip("192.168.4.2")]] == [22, 53, 80]


@pytest.mark.parametrize(
    ("platform", "expected"),
    [
        ("linux", ["ping", "-c", "1", "-W", "1", "-n", "192.168.4.1"]),
        ("darwin", ["ping", "-c", "1", "-t", "1", "-n", "192.168.4.1"]),
        ("win32", ["ping", "-n", "1", "-w", "1000", "192.168.4.1"]),
    ],
)
def test_ping_argv_is_allowlisted(platform: str, expected: list[str]) -> None:
    argv = ping_argv(platform, ip("192.168.4.1"), 1.0)
    assert argv == expected
    ALLOWLIST.check(argv)


def test_windows_unreachable_is_not_a_reply() -> None:
    assert not is_ping_reply(0, "Reply from 192.168.4.1: Destination host unreachable.\n")
    assert is_ping_reply(0, "Reply from 192.168.4.1: bytes=32 time<1ms TTL=64\n")
    assert is_ping_reply(0, LINUX_REPLY)
    assert not is_ping_reply(1, "")


@pytest.mark.parametrize(
    "argv",
    [
        ["ping", "-c", "1", "-W", "1", "-n", "192.168.4.1;reboot"],
        ["ping", "-c", "1", "-W", "1", "-n", "example.com"],
        ["nmap", "-sS", "-O", "192.168.4.1"],
        ["arp", "-d", "192.168.4.1"],
        ["sh", "-c", "ping 192.168.4.1"],
    ],
)
def test_local_runner_refuses_off_list_commands(argv: list[str]) -> None:
    with pytest.raises(ReadOnlyViolation):
        _run_local(argv)


# --- options --------------------------------------------------------------------------------


def test_too_many_hosts_is_rejected() -> None:
    with pytest.raises(ValidationError, match="max_hosts"):
        DiscoveryOptions(subnets=["10.0.0.0/16"])
    DiscoveryOptions(subnets=["10.0.0.0/22"], max_hosts=1024)


def test_hard_ceiling_cannot_be_raised() -> None:
    with pytest.raises(ValidationError):
        DiscoveryOptions(subnets=["10.0.0.0/16"], max_hosts=70000)


@pytest.mark.parametrize("subnets", [[], ["fd00::/64"], ["not-a-subnet"]])
def test_bad_subnets_are_rejected(subnets: list[str]) -> None:
    with pytest.raises(ValidationError):
        DiscoveryOptions(subnets=subnets)
