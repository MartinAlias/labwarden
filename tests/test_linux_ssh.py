from __future__ import annotations

import json
import logging
import re
import shlex
import shutil
import subprocess
from collections.abc import Sequence
from ipaddress import ip_address, ip_interface, ip_network
from pathlib import Path
from typing import ClassVar

import paramiko
import pytest

from labwarden.collectors import ReadOnlyViolation, linux_ssh
from labwarden.collectors.linux_ssh import (
    ALLOWLIST,
    COMMANDS,
    LinuxSshCollector,
    LinuxSshOptions,
    SshCommandError,
    parse_nft,
)

ROOT = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures" / "linux_ssh"
WRAPPER = ROOT / "deploy" / "ssh" / "labwarden-ssh-wrapper.sh"

OUTPUTS = {
    "addr": "ip_addr.json",
    "route4": "ip_route.json",
    "route6": "ip6_route.json",
    "sockets": "ss.txt",
    "os": "os-release.txt",
    "resolv": "resolv.conf",
    "resolvectl": "resolvectl_dns.txt",
    "nft": "nft.json",
}


class FakeHost:
    """Answers each allowlisted command with its fixture; records what was run."""

    def __init__(self, missing: Sequence[str] = ()) -> None:
        self.by_cmd = {
            shlex.join(COMMANDS[k]): (FIXTURES / f).read_text(encoding="utf-8")
            for k, f in OUTPUTS.items()
            if k not in missing
        }
        self.ran: list[str] = []

    def __call__(self, argv: Sequence[str]) -> tuple[int, str, str]:
        assert ALLOWLIST.is_allowed(argv), argv
        cmd = shlex.join(argv)
        self.ran.append(cmd)
        if cmd not in self.by_cmd:
            return 127, "", f"sh: 1: {argv[0]}: not found"
        return 0, self.by_cmd[cmd], ""


def _collector(fake: FakeHost, **options: object) -> LinuxSshCollector:
    opts = LinuxSshOptions.model_validate(
        {"host": "192.168.20.10", "key_file": "id_ed25519", **options}
    )
    collector = LinuxSshCollector("docker-server", opts, Path("."))
    collector._runner = fake
    return collector


def test_device() -> None:
    model = _collector(FakeHost()).collect()
    (device,) = model.devices
    assert device.name == "docker-server"
    assert device.os == "Ubuntu 24.04.1 LTS"
    assert device.management_ip == ip_address("192.168.20.10")
    # resolvectl's real upstream wins over the 127.0.0.53 stub in resolv.conf.
    assert device.tags == ["dns-server:192.168.20.2"]


def test_interfaces_and_addresses() -> None:
    model = _collector(FakeHost()).collect()
    ifaces = {i.name: i for i in model.interfaces}
    assert sorted(ifaces) == ["docker0", "enp1s0", "enp1s0.20", "wg0"]  # no lo, no veth
    assert ifaces["enp1s0.20"].vlan_id == 20
    assert ifaces["enp1s0.20"].mac == "02:00:00:00:10:01"
    assert ifaces["docker0"].state == "down"
    assert ifaces["wg0"].state == "up"  # operstate UNKNOWN but LOWER_UP
    assert ifaces["wg0"].mac is None

    addrs = {(a.interface, a.address, a.dhcp) for a in model.addresses}
    assert addrs == {
        ("enp1s0.20", ip_interface("192.168.20.10/24"), True),
        ("docker0", ip_interface("172.17.0.1/16"), False),
        ("wg0", ip_interface("10.8.0.1/24"), False),
    }


def test_routes() -> None:
    model = _collector(FakeHost()).collect()
    routes = {(str(r.destination), str(r.gateway) if r.gateway else None) for r in model.routes}
    assert ("0.0.0.0/0", "192.168.20.1") in routes
    assert ("192.168.20.1/32", None) in routes
    assert ("fe80::/64", None) in routes
    assert not any(dst in ("10.99.0.0/16", "ff00::/8") for dst, _ in routes)  # non-unicast
    default = next(r for r in model.routes if r.destination == ip_network("0.0.0.0/0"))
    assert default.interface == "enp1s0.20" and default.metric == 100


def test_listening_sockets() -> None:
    model = _collector(FakeHost()).collect()
    services = {(s.protocol, str(s.address), s.port, s.process) for s in model.services}
    assert len(services) == len(model.services) == 11
    assert ("udp", "127.0.0.53", 53, "systemd-resolve") in services  # %lo stripped
    assert ("udp", "0.0.0.0", 51820, None) in services  # no process info without root
    assert ("tcp", "::", 22, "sshd") in services
    assert ("tcp", "::", 9100, "node_exporter") in services  # "*" is dual-stack


def test_nft_is_opt_in() -> None:
    fake = FakeHost()
    model = _collector(fake).collect()
    assert model.firewall_rules == []
    assert not any("nft" in cmd for cmd in fake.ran)


def test_nft_rules() -> None:
    model = _collector(FakeHost(), nftables=True).collect()
    rules = model.firewall_rules
    assert len(rules) == 11
    input_rules = [r for r in rules if r.chain == "inet filter input"]
    assert [r.order for r in input_rules] == list(range(8))
    assert all(r.direction == "in" for r in input_rules)

    established, lo, ssh, web, wireguard, ping, reject, policy = input_rules
    assert established.action == "allow"
    assert established.description == "ct state in established,related"
    assert lo.description == "meta iifname == lo"
    assert (ssh.protocol, ssh.src, ssh.dst_port) == ("tcp", "192.168.10.67", "22")
    assert ssh.description == "ssh from admin pc"
    assert (web.src, web.dst_port) == ("192.168.10.0/24", "80,443,8096")
    assert (wireguard.protocol, wireguard.dst_port) == ("udp", "51820")
    assert ping.protocol == "icmp" and "echo-request" in ping.description
    assert (reject.action, reject.dst_port) == ("reject", "6000-6010")
    assert (policy.action, policy.description) == ("block", "default policy")

    by_chain = {(r.chain, r.order): r for r in rules}
    assert by_chain[("inet filter forward", 0)].description == "default policy"  # jump skipped
    assert by_chain[("inet filter output", 0)].action == "allow"
    docker_user = by_chain[("inet filter docker-user", 0)]
    assert (docker_user.action, docker_user.direction) == ("block", "any")
    assert not any("nat" in r.chain for r in rules)


def test_nft_unknown_matches_are_described_not_dropped() -> None:
    ruleset = {
        "nftables": [
            {
                "chain": {
                    "family": "ip",
                    "table": "t",
                    "name": "c",
                    "type": "filter",
                    "hook": "input",
                }
            },
            {
                "rule": {
                    "family": "ip",
                    "table": "t",
                    "chain": "c",
                    "expr": [
                        {"match": {"op": "!=", "left": {"meta": {"key": "mark"}}, "right": 7}},
                        {"drop": None},
                    ],
                }
            },
        ]
    }
    (rule,) = parse_nft("h", ruleset)
    assert rule.src == "any" and rule.description == "meta mark != 7"


def test_resolv_conf_fallback_without_resolvectl() -> None:
    model = _collector(FakeHost(missing=["resolvectl"])).collect()
    assert model.devices[0].tags == ["dns-server:127.0.0.53"]


def test_optional_command_failure_is_a_warning(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        model = _collector(FakeHost(missing=["os"])).collect()
    assert model.devices[0].os is None
    assert "os-release" in caplog.text


def test_required_command_failure_is_an_error() -> None:
    with pytest.raises(SshCommandError, match="ip -d -j addr"):
        _collector(FakeHost(missing=["addr"])).collect()


def test_only_allowlisted_commands_run() -> None:
    fake = FakeHost()
    _collector(fake, nftables=True).collect()
    assert set(fake.ran) <= {shlex.join(c) for c in COMMANDS.values()}


# --- the SSH session ------------------------------------------------------------------------


class FakeSSHClient:
    instances: ClassVar[list[FakeSSHClient]] = []

    def __init__(self) -> None:
        self.policy: object = None
        self.connect_kwargs: dict[str, object] = {}
        self.commands: list[str] = []
        FakeSSHClient.instances.append(self)

    def load_system_host_keys(self) -> None: ...

    def load_host_keys(self, path: str) -> None: ...

    def set_missing_host_key_policy(self, policy: object) -> None:
        self.policy = policy

    def connect(self, host: str, **kwargs: object) -> None:
        self.connect_kwargs = kwargs

    def exec_command(self, command: str, timeout: float) -> tuple:
        self.commands.append(command)
        raise AssertionError("tests never execute a command")

    def close(self) -> None: ...


def test_ssh_session_rejects_unknown_hosts_and_off_list_commands(monkeypatch) -> None:
    monkeypatch.setattr(paramiko, "SSHClient", FakeSSHClient)
    opts = LinuxSshOptions(host="192.168.20.10", key_file=Path("k"))
    with linux_ssh.SshSession(opts, Path(".")) as session:
        client = FakeSSHClient.instances[-1]
        assert isinstance(client.policy, paramiko.RejectPolicy)
        assert client.connect_kwargs["allow_agent"] is False
        assert client.connect_kwargs["look_for_keys"] is False
        for argv in (["rm", "-rf", "/"], ["ip", "-j", "route", ";", "reboot"], ["sh"]):
            with pytest.raises(ReadOnlyViolation):
                session.run(argv)
    assert client.commands == []


# --- the remote wrapper ---------------------------------------------------------------------

_CASE = re.compile(r'^\s*"([^"]+)"\)\s+exec (.+?) ;;$', re.MULTILINE)


def test_wrapper_matches_the_collector_allowlist() -> None:
    cases = _CASE.findall(WRAPPER.read_text(encoding="utf-8"))
    assert {pattern for pattern, _ in cases} == {shlex.join(c) for c in COMMANDS.values()}
    for pattern, executed in cases:
        assert pattern == executed  # it runs exactly what it matched, nothing more


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX sh")
@pytest.mark.parametrize(
    "requested",
    ["", "rm -rf /", "ip -j route; reboot", "ip -j route ", "ip -j route && id", "IP -j route"],
)
def test_wrapper_refuses_everything_else(requested: str) -> None:
    # Absolute path: on POSIX, subprocess looks the program up in the *child's* PATH,
    # which is deliberately empty here so the wrapper can't run any real command.
    sh = shutil.which("sh")
    assert sh is not None
    result = subprocess.run(
        [sh, str(WRAPPER)],
        env={"SSH_ORIGINAL_COMMAND": requested, "PATH": "/nonexistent"},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 126
    assert "not allowed" in result.stderr


def test_every_command_is_allowlisted_and_json_fixtures_parse() -> None:
    for argv in COMMANDS.values():
        ALLOWLIST.check(argv)
    for name in ("ip_addr.json", "ip_route.json", "ip6_route.json", "nft.json"):
        json.loads((FIXTURES / name).read_text(encoding="utf-8"))
