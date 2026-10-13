"""Where probes run: on the LabWarden host, or on a Linux host over SSH.

Both paths only run argv lists that ``PROBE_ALLOWLIST`` accepts. Remote probes
are further limited to ``REMOTE_ALLOWLIST``, which
``deploy/ssh/labwarden-ssh-wrapper.sh`` mirrors argument by argument.
``tests/test_probes.py`` runs both against the same inputs.
"""

from __future__ import annotations

import sys
import threading
import time
from collections.abc import Callable, Sequence
from types import TracebackType
from typing import Protocol

from labwarden.collectors.allowlist import CommandAllowlist
from labwarden.collectors.linux_ssh import LinuxSshOptions, SshSession
from labwarden.config import Config
from labwarden.local_exec import CommandResult, run_local

# Argument shapes. Hosts and names never start with "-", so they can't be read as options.
HOST = r"re:[A-Za-z0-9.:][A-Za-z0-9.:-]{0,252}"
DNS_NAME = r"re:[A-Za-z0-9_][A-Za-z0-9._-]{0,252}"
DNS_SERVER = r"re:@[A-Za-z0-9.:][A-Za-z0-9.:-]{0,252}"
RECORD_TYPE = r"re:A|AAAA|CNAME|MX|TXT|NS|PTR|SOA|SRV"
PORT = r"re:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]"
URL = r"re:https?://[A-Za-z0-9.:/%+=_-]{1,2000}"
ONE_TO_FIVE = r"re:[1-5]"
ONE_TO_NINE = r"re:[1-9]"
ONE_TO_THIRTY = r"re:[1-9]|[12][0-9]|30"

#: Runs on Linux hosts through the SSH wrapper (and locally on Linux).
REMOTE_PATTERNS: list[tuple[str, ...]] = [
    ("ping", "-c", ONE_TO_FIVE, "-W", ONE_TO_FIVE, "-n", HOST),
    ("traceroute", "-n", "-q", "1", "-w", "2", "-m", ONE_TO_THIRTY, HOST),
    ("dig", "+time=2", "+tries=1", "+noall", "+comments", "+answer", DNS_NAME, RECORD_TYPE),
    (
        "dig",
        "+time=2",
        "+tries=1",
        "+noall",
        "+comments",
        "+answer",
        DNS_SERVER,
        DNS_NAME,
        RECORD_TYPE,
    ),
    ("nc", "-z", "-w", ONE_TO_NINE, HOST, PORT),
    ("curl", "-sS", "-I", "-m", ONE_TO_THIRTY, URL),
]
#: Local-only variants for Windows and macOS. DNS, TCP and HTTP run in Python locally.
LOCAL_ONLY_PATTERNS: list[tuple[str, ...]] = [
    ("ping", "-n", ONE_TO_FIVE, "-w", r"re:[1-5]000", HOST),  # Windows
    ("ping", "-c", ONE_TO_FIVE, "-t", ONE_TO_FIVE, "-n", HOST),  # macOS
    ("tracert", "-d", "-h", ONE_TO_THIRTY, "-w", "2000", HOST),  # Windows
]
REMOTE_ALLOWLIST = CommandAllowlist(REMOTE_PATTERNS)
PROBE_ALLOWLIST = CommandAllowlist(REMOTE_PATTERNS + LOCAL_ONLY_PATTERNS)


class Executor(Protocol):
    #: "local", or the name of the linux_ssh target the probe ran from.
    source: str
    #: ``sys.platform`` style: "linux", "win32", "darwin".
    platform: str
    #: True when the probe runs over SSH; DNS/TCP/HTTP then use dig/nc/curl.
    remote: bool

    def run(self, argv: Sequence[str]) -> CommandResult: ...


class LocalExecutor:
    source = "local"
    remote = False

    def __init__(self, platform: str = sys.platform, timeout: float = 120) -> None:
        self.platform = platform
        self._timeout = timeout

    def run(self, argv: Sequence[str]) -> CommandResult:
        return run_local(argv, PROBE_ALLOWLIST, timeout=self._timeout)


class RemoteExecutor:
    """Runs probes from a Linux host, reusing a ``linux_ssh`` target's credentials."""

    platform = "linux"
    remote = True

    def __init__(self, source: str, session: SshSession) -> None:
        self.source = source
        self._session = session

    def __enter__(self) -> RemoteExecutor:
        self._session.__enter__()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._session.__exit__(exc_type, exc, tb)

    def run(self, argv: Sequence[str]) -> CommandResult:
        return self._session.run(argv)


def remote_executor(config: Config, target_name: str) -> RemoteExecutor:
    """Build an executor for ``--from <target>``; the target must use ``linux_ssh``."""
    target = next((t for t in config.targets if t.name == target_name), None)
    if target is None:
        raise LookupError(f"no target named {target_name!r} in the config")
    if target.plugin != "linux_ssh":
        raise LookupError(
            f"target {target_name!r} uses plugin {target.plugin!r}; probes can only run "
            "from linux_ssh targets"
        )
    opts = LinuxSshOptions.model_validate(target.options)
    return RemoteExecutor(target_name, SshSession(opts, config.base_dir, REMOTE_ALLOWLIST))


class RateLimiter:
    """Token bucket: on average ``rate`` probes per second, bursts up to ``burst``."""

    def __init__(
        self,
        rate: float,
        burst: int,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if rate <= 0 or burst < 1:
            raise ValueError("rate must be > 0 and burst >= 1")
        self._rate, self._burst = rate, burst
        self._clock, self._sleep = clock, sleep
        self._tokens = float(burst)
        self._last = clock()
        self._lock = threading.Lock()

    def acquire(self) -> float:
        """Take one token, sleeping until it's available. Returns the time waited."""
        with self._lock:
            now = self._clock()
            self._tokens = min(self._burst, self._tokens + (now - self._last) * self._rate)
            self._last = now
            self._tokens -= 1  # may go negative: a reservation the caller waits out
            wait = 0.0 if self._tokens >= 0 else -self._tokens / self._rate
        if wait:
            self._sleep(wait)
        return wait


#: Shared by every probe in this process, so a chatty agent can't flood the network.
DEFAULT_LIMITER = RateLimiter(rate=2.0, burst=5)
