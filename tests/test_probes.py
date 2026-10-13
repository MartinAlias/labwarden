from __future__ import annotations

import shlex
import shutil
import socket
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import ClassVar

import dns.resolver
import httpx
import paramiko
import pytest
from typer.testing import CliRunner

from labwarden.cli import app
from labwarden.collectors import CommandAllowlist, ReadOnlyViolation
from labwarden.collectors.linux_ssh import LinuxSshOptions, SshSession
from labwarden.config import Config, TargetConfig
from labwarden.probes import (
    RateLimiter,
    dns_resolve,
    http_head,
    ping,
    remote_executor,
    tcp_connect,
    traceroute,
)
from labwarden.probes.execution import PROBE_ALLOWLIST, REMOTE_ALLOWLIST

ROOT = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures" / "probes"
WRAPPER = ROOT / "deploy" / "ssh" / "labwarden-ssh-wrapper.sh"


def _fx(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class NoWait(RateLimiter):
    def __init__(self) -> None:
        super().__init__(rate=1000, burst=1000)


class FakeExecutor:
    """Answers commands from a table; checks every argv against the right allowlist."""

    def __init__(
        self,
        replies: dict[str, tuple[int, str, str]] | None = None,
        *,
        platform: str = "linux",
        remote: bool = False,
    ) -> None:
        self.replies = replies or {}
        self.platform = platform
        self.remote = remote
        self.source = "docker-server-host" if remote else "local"
        self.ran: list[list[str]] = []

    def run(self, argv: Sequence[str]) -> tuple[int, str, str]:
        if self.remote:
            REMOTE_ALLOWLIST.check(argv)
            assert shlex.join(argv) == " ".join(argv), "remote argv must not need quoting"
        else:
            PROBE_ALLOWLIST.check(argv)
        self.ran.append(list(argv))
        return self.replies.get(argv[0], (127, "", f"{argv[0]}: not found"))


LIMIT = NoWait()


# --- ping ---------------------------------------------------------------------------------


def test_ping_linux() -> None:
    ex = FakeExecutor({"ping": (0, _fx("ping_linux.txt"), "")})
    r = ping("192.168.20.2", executor=ex, limiter=LIMIT)
    assert ex.ran == [["ping", "-c", "3", "-W", "2", "-n", "192.168.20.2"]]
    assert r.ok and r.data["received"] == 2 and r.data["avg_rtt_ms"] == 0.4
    assert r.summary == "2/3 replies from 192.168.20.2, avg 0.4 ms"


def test_ping_linux_total_loss() -> None:
    ex = FakeExecutor({"ping": (1, _fx("ping_linux_loss.txt"), "")})
    r = ping("192.168.30.40", executor=ex, limiter=LIMIT)
    assert not r.ok and r.summary == "no reply from 192.168.30.40 (3 sent)"


def test_ping_windows() -> None:
    ex = FakeExecutor({"ping": (0, _fx("ping_windows.txt"), "")}, platform="win32")
    r = ping("192.168.4.1", executor=ex, limiter=LIMIT)
    assert ex.ran == [["ping", "-n", "3", "-w", "2000", "192.168.4.1"]]
    assert r.ok and r.data["received"] == 3 and r.data["avg_rtt_ms"] == 1


def test_ping_windows_unreachable_is_not_a_reply() -> None:
    # Windows counts "Destination host unreachable" as Received = 3.
    ex = FakeExecutor({"ping": (0, _fx("ping_windows_unreachable.txt"), "")}, platform="win32")
    r = ping("192.168.30.40", executor=ex, limiter=LIMIT)
    assert not r.ok and r.data["received"] == 0


def test_missing_tool_is_a_result_not_a_crash() -> None:
    r = ping("192.168.4.1", executor=FakeExecutor(), limiter=LIMIT)
    assert not r.ok and "not installed" in r.summary


# --- traceroute ---------------------------------------------------------------------------


def test_traceroute_linux_reaches_destination() -> None:
    ex = FakeExecutor({"traceroute": (0, _fx("traceroute_linux.txt"), "")})
    r = traceroute("1.1.1.1", executor=ex, limiter=LIMIT)
    assert r.ok and r.summary == "reached 1.1.1.1 in 5 hops"
    assert r.data["hops"][2] == {"hop": 3, "ip": None, "rtt_ms": None}
    assert r.data["hops"][0] == {"hop": 1, "ip": "192.168.20.1", "rtt_ms": 0.512}


def test_traceroute_stops_at_the_firewall() -> None:
    ex = FakeExecutor({"traceroute": (0, _fx("traceroute_linux_blocked.txt"), "")})
    r = traceroute("192.168.50.20", executor=ex, limiter=LIMIT)
    assert not r.ok
    assert r.summary == "did not reach 192.168.50.20; last reply from hop 1 (192.168.20.1)"


def test_tracert_windows() -> None:
    ex = FakeExecutor({"tracert": (0, _fx("tracert_windows.txt"), "")}, platform="win32")
    r = traceroute("one.one.one.one", executor=ex, limiter=LIMIT)
    assert ex.ran[0][:2] == ["tracert", "-d"]
    assert r.ok and r.data["destination"] == "1.1.1.1"  # from the "[1.1.1.1]" header
    assert r.data["hops"][0]["rtt_ms"] == 1.0 and r.data["hops"][2]["ip"] is None


# --- DNS ----------------------------------------------------------------------------------


def test_dig_remote_answer_keeps_only_the_requested_type() -> None:
    ex = FakeExecutor({"dig": (0, _fx("dig_noerror.txt"), "")}, remote=True)
    r = dns_resolve("www.example.com", server="192.168.20.2", executor=ex, limiter=LIMIT)
    assert "@192.168.20.2" in ex.ran[0]
    assert r.ok and r.data["answers"] == ["93.184.215.14"]
    assert r.summary == "www.example.com A -> 93.184.215.14 (via 192.168.20.2)"


def test_dig_nxdomain() -> None:
    ex = FakeExecutor({"dig": (0, _fx("dig_nxdomain.txt"), "")}, remote=True)
    r = dns_resolve("nas.lan", executor=ex, limiter=LIMIT)
    assert not r.ok and r.data["status"] == "NXDOMAIN"
    assert ex.ran[0][-2:] == ["nas.lan", "A"]


def test_dig_flags_a_blocked_domain() -> None:
    ex = FakeExecutor({"dig": (0, _fx("dig_blocked.txt"), "")}, remote=True)
    r = dns_resolve("doubleclick.net", server="192.168.20.2", executor=ex, limiter=LIMIT)
    assert r.ok and r.data["blocked_hint"] is True
    assert "looks blocked by a DNS filter" in r.summary


def test_dig_missing_has_an_install_hint() -> None:
    r = dns_resolve("nas.lan", executor=FakeExecutor(remote=True), limiter=LIMIT)
    assert not r.ok and "dnsutils" in (r.error or "")


class _Rdata:
    def __init__(self, text: str) -> None:
        self.text = text

    def to_text(self) -> str:
        return self.text


class _Answer:
    rrset: ClassVar[list[_Rdata]] = [_Rdata("192.168.20.10")]
    nameserver = "192.168.20.2"


def test_dns_local_uses_dnspython(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_resolve(self, name, rtype, **kwargs):
        seen.update(name=name, rtype=rtype, ns=self.nameservers)
        return _Answer()

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", fake_resolve)
    r = dns_resolve("docker.lan", server="192.168.20.2", limiter=LIMIT)
    assert seen == {"name": "docker.lan", "rtype": "A", "ns": ["192.168.20.2"]}
    assert r.ok and r.source == "local" and r.data["answers"] == ["192.168.20.10"]


def test_dns_local_nxdomain(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_resolve(self, *a, **kw):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", fake_resolve)
    r = dns_resolve("nope.lan", server="192.168.20.2", limiter=LIMIT)
    assert not r.ok and r.data["status"] == "NXDOMAIN"


# --- TCP ----------------------------------------------------------------------------------


def test_tcp_local_open() -> None:
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        r = tcp_connect("127.0.0.1", port, limiter=LIMIT)
    assert r.ok and r.data["state"] == "open" and r.target == f"127.0.0.1:{port}"


def test_tcp_local_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*a, **kw):
        raise ConnectionRefusedError

    monkeypatch.setattr(socket, "create_connection", refuse)
    r = tcp_connect("192.168.20.10", 8096, limiter=LIMIT)
    assert not r.ok and "nothing listening" in r.summary


NC_OPEN = "Connection to 192.168.20.2 53 port [tcp/domain] succeeded!"
NC_REFUSED = "nc: connect to 192.168.20.2 port 81 (tcp) failed: Connection refused"
NC_TIMEOUT = "nc: connect to 192.168.50.20 port 22 (tcp) timed out: Operation now in progress"


@pytest.mark.parametrize(
    ("reply", "state"),
    [
        ((0, "", NC_OPEN), "open"),
        ((1, "", NC_REFUSED), "refused"),
        ((1, "", NC_TIMEOUT), "timeout"),
    ],
)
def test_tcp_remote_via_nc(reply: tuple[int, str, str], state: str) -> None:
    ex = FakeExecutor({"nc": reply}, remote=True)
    r = tcp_connect("192.168.20.2", 53, executor=ex, limiter=LIMIT)
    assert ex.ran == [["nc", "-z", "-w", "3", "192.168.20.2", "53"]]
    assert r.data["state"] == state and r.ok is (state == "open")


# --- HTTP ---------------------------------------------------------------------------------


def test_http_local_reports_redirect_without_following() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "HEAD"
        return httpx.Response(301, headers={"location": "https://nas.lan/", "server": "nginx"})

    r = http_head("http://nas.lan/", limiter=LIMIT, _transport=httpx.MockTransport(handler))
    assert r.ok and r.data["status_code"] == 301
    assert r.summary == "HTTP 301 from http://nas.lan/ -> https://nas.lan/ (server: nginx)"


def test_http_local_connection_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("[Errno 111] Connection refused")

    r = http_head("http://nas.lan/", limiter=LIMIT, _transport=httpx.MockTransport(handler))
    assert not r.ok and r.data["state"] == "connect_error"


def test_http_remote_via_curl() -> None:
    ex = FakeExecutor({"curl": (0, _fx("curl_head.txt"), "")}, remote=True)
    r = http_head("http://jellyfin.lan/", executor=ex, limiter=LIMIT)
    assert ex.ran == [["curl", "-sS", "-I", "-m", "5", "http://jellyfin.lan/"]]
    assert r.data["status_code"] == 301 and r.data["server"] == "nginx/1.27.2"
    assert r.data["location"] == "https://jellyfin.lan/web/"


# --- input validation (these become AI tools) ---------------------------------------------


@pytest.mark.parametrize(
    "call",
    [
        lambda: ping("-oProxyCommand=sh", limiter=LIMIT),
        lambda: ping("a;reboot", limiter=LIMIT),
        lambda: ping("", limiter=LIMIT),
        lambda: ping("192.168.4.1", count=6, limiter=LIMIT),
        lambda: traceroute("1.1.1.1", max_hops=31, limiter=LIMIT),
        lambda: tcp_connect("nas.lan", 0, limiter=LIMIT),
        lambda: tcp_connect("nas.lan", 65536, limiter=LIMIT),
        lambda: dns_resolve("-x", limiter=LIMIT),
        lambda: dns_resolve("nas.lan", record_type="ANY", limiter=LIMIT),
        lambda: dns_resolve("nas.lan", server="pihole.lan", limiter=LIMIT),
        lambda: http_head("ftp://nas.lan/", limiter=LIMIT),
        lambda: http_head("http://admin:pw@nas.lan/", limiter=LIMIT),
        lambda: http_head("http://nas.lan/#x", limiter=LIMIT),
        lambda: http_head("http://nas.lan/?a=b", executor=FakeExecutor(remote=True), limiter=LIMIT),
    ],
)
def test_bad_inputs_are_rejected_before_anything_runs(call) -> None:
    with pytest.raises(ValueError):
        call()


def test_query_strings_are_fine_locally() -> None:
    transport = httpx.MockTransport(lambda req: httpx.Response(204))
    assert http_head("http://nas.lan/health?full=1", limiter=LIMIT, _transport=transport).ok


# --- rate limiting --------------------------------------------------------------------------


def test_rate_limiter_allows_a_burst_then_spaces_calls() -> None:
    now = [0.0]
    slept: list[float] = []

    def sleep(seconds: float) -> None:
        slept.append(seconds)

    limiter = RateLimiter(rate=2.0, burst=2, clock=lambda: now[0], sleep=sleep)
    for _ in range(4):
        limiter.acquire()
    assert slept == [0.5, 1.0]  # third waits one interval, fourth waits two
    now[0] = 10.0  # long idle: the bucket refills to the burst size, not beyond
    slept.clear()
    for _ in range(3):
        limiter.acquire()
    assert slept == [0.5]


# --- remote execution -----------------------------------------------------------------------


def _config(tmp_path: Path) -> Config:
    config = Config(
        targets=[
            TargetConfig(name="pihole", plugin="pihole", options={"url": "http://192.168.20.2"}),
            TargetConfig(
                name="docker-server-host",
                plugin="linux_ssh",
                options={"host": "192.168.20.10", "key_file": "k"},
            ),
        ]
    )
    config._base_dir = tmp_path
    return config


def test_remote_executor_needs_a_linux_ssh_target(tmp_path: Path) -> None:
    config = _config(tmp_path)
    with pytest.raises(LookupError, match="linux_ssh"):
        remote_executor(config, "pihole")
    with pytest.raises(LookupError, match="no target"):
        remote_executor(config, "nope")
    ex = remote_executor(config, "docker-server-host")
    assert ex.source == "docker-server-host" and ex.remote
    assert ex._session._allowlist is REMOTE_ALLOWLIST


class _FakeClient:
    def load_system_host_keys(self) -> None: ...

    def set_missing_host_key_policy(self, policy: object) -> None: ...

    def connect(self, *a: object, **kw: object) -> None: ...

    def exec_command(self, *a: object, **kw: object):
        raise AssertionError("must not be reached")

    def close(self) -> None: ...


def test_ssh_session_refuses_arguments_that_need_quoting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(paramiko, "SSHClient", _FakeClient)
    loose = CommandAllowlist([("echo", "re:.*")])
    opts = LinuxSshOptions(host="192.168.20.10", key_file=Path("k"))
    with SshSession(opts, Path("."), loose) as session, pytest.raises(ReadOnlyViolation):
        session.run(["echo", "two words"])


# --- the wrapper must agree with REMOTE_ALLOWLIST -------------------------------------------

AGREEMENT_CASES = [
    # accepted
    "ping -c 3 -W 2 -n 192.168.20.2",
    "ping -c 5 -W 5 -n fd00::2",
    "traceroute -n -q 1 -w 2 -m 30 1.1.1.1",
    "dig +time=2 +tries=1 +noall +comments +answer nas.lan A",
    "dig +time=2 +tries=1 +noall +comments +answer @192.168.20.2 _ldap._tcp.lab.local SRV",
    "nc -z -w 3 192.168.20.2 53",
    "nc -z -w 9 nas.lan 65535",
    "curl -sS -I -m 5 http://jellyfin.lan:8096/web/",
    "curl -sS -I -m 30 https://192.168.20.10/api/health",
    # refused
    "ping -c 6 -W 2 -n 192.168.20.2",
    "ping -c 05 -W 2 -n 192.168.20.2",
    "ping -c 3 -W 2 -n -oProxy",
    "ping -c 3 -W 2 -n 192.168.20.2 extra",
    "ping -c 3 -W 2 -n",
    "ping -c 3 -W 2 -f 192.168.20.2",
    "traceroute -n -q 1 -w 2 -m 31 1.1.1.1",
    "traceroute -n -q 2 -w 2 -m 20 1.1.1.1",
    "dig +time=2 +tries=1 +noall +comments +answer nas.lan ANY",
    "dig +time=2 +tries=1 +noall +comments +answer .nas.lan A",
    "dig +time=2 +tries=1 +noall +comments +answer @-x nas.lan A",
    "dig +time=9 +tries=1 +noall +comments +answer nas.lan A",
    "dig +time=2 +tries=1 +noall +comments +answer @1.1.1.1 nas.lan A extra",
    "nc -z -w 3 192.168.20.2 65536",
    "nc -z -w 3 192.168.20.2 0",
    "nc -z -w 3 192.168.20.2 080",
    "nc -l -w 3 192.168.20.2 80",
    "nc -z -w 10 192.168.20.2 80",
    "curl -sS -I -m 5 ftp://nas.lan/",
    "curl -sS -I -m 5 http://",
    "curl -sS -I -m 5 http://nas.lan/?a=b",
    "curl -sS -I -m 31 http://nas.lan/",
    "curl -sS -X POST -m 5 http://nas.lan/",
    "curl -sS -I -m 5 http://nas.lan/ -o /etc/passwd",
    "ping -c 3 -W 2 -n 1.1.1.1;reboot",
    "ping -c 3 -W 2 -n $(reboot)",
    "sh -c id",
    "bash",
]


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX sh")
@pytest.mark.parametrize("command", AGREEMENT_CASES)
def test_wrapper_and_python_allowlist_agree(command: str) -> None:
    argv = command.split(" ")
    python_allows = REMOTE_ALLOWLIST.is_allowed(argv)
    sh = shutil.which("sh")
    assert sh is not None
    # PATH is empty, so an accepted command fails at exec (127) instead of running.
    result = subprocess.run(
        [sh, str(WRAPPER)],
        env={"SSH_ORIGINAL_COMMAND": command, "PATH": "/nonexistent"},
        capture_output=True,
        text=True,
        timeout=10,
    )
    wrapper_allows = result.returncode != 126
    assert python_allows == wrapper_allows, (command, result.returncode, result.stderr)


# --- CLI ------------------------------------------------------------------------------------

runner = CliRunner()


def test_cli_tcp_probe_against_a_local_listener() -> None:
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        result = runner.invoke(app, ["probe", "tcp", "127.0.0.1", str(port)])
    assert result.exit_code == 0, result.output
    assert "open" in result.output


def test_cli_rejects_bad_input() -> None:
    result = runner.invoke(app, ["probe", "dns", "nas.lan", "--server", "pihole.lan"])
    assert result.exit_code == 2


def test_cli_from_unknown_target(lab_dir: Path) -> None:
    config = str(lab_dir / "labwarden.yaml")
    result = runner.invoke(app, ["probe", "ping", "1.1.1.1", "--from", "nope", "-c", config])
    assert result.exit_code == 2
