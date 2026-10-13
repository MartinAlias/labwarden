"""Safe, read-only network probes.

Each probe sends a handful of packets at most and changes nothing. They are
the "test" step of diagnosis ("can the NAS reach its gateway?") and of fix
verification. Every probe:

* validates its inputs strictly (these become AI tools, so treat inputs as untrusted)
* waits for the shared rate limiter
* runs locally, or on a Linux host when given a ``RemoteExecutor``
* never raises for network failures; they become ``ok=False`` with a summary
"""

from __future__ import annotations

import re
import socket
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit

import dns.exception
import dns.resolver
import httpx

from labwarden.collectors.base import ReadOnlyViolation
from labwarden.probes.execution import DEFAULT_LIMITER, Executor, LocalExecutor, RateLimiter
from labwarden.probes.models import ProbeResult

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SOA", "SRV")
_HOST = re.compile(r"[A-Za-z0-9.:][A-Za-z0-9.:-]{0,252}")
_DNS_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,252}")
_URL_CHARS = re.compile(r"[A-Za-z0-9.:/%+=_-]{1,2000}")
_URL_QUERY_CHARS = re.compile(r"[A-Za-z0-9.:/%+=_?&~-]{1,2000}")  # local only


# --- input validation ---------------------------------------------------------------------


def _host(value: str) -> str:
    if not _HOST.fullmatch(value):
        raise ValueError(f"not a valid host name or IP address: {value!r}")
    return value


def _int(value: int, low: int, high: int, what: str) -> int:
    if not low <= value <= high:
        raise ValueError(f"{what} must be between {low} and {high}, got {value}")
    return value


def _url(value: str, *, remote: bool) -> str:
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"only http:// and https:// URLs can be probed: {value!r}")
    if parts.username or parts.password:
        raise ValueError("URLs with credentials are not allowed")
    if parts.fragment:
        raise ValueError("URL fragments (#...) are not allowed")
    rest = value.split("://", 1)[1]
    chars = _URL_CHARS if remote else _URL_QUERY_CHARS
    if not chars.fullmatch(rest):
        hint = " (remote probes can't use ? & or ~)" if remote else ""
        raise ValueError(f"URL has characters that aren't allowed{hint}: {value!r}")
    _host(parts.hostname)
    return value


# --- plumbing -----------------------------------------------------------------------------


@contextmanager
def _timed() -> Iterator[Callable[[], float]]:
    start = time.perf_counter()
    yield lambda: round((time.perf_counter() - start) * 1000, 1)


def _result(probe: str, target: str, ex: Executor, elapsed: float, **kw: Any) -> ProbeResult:
    return ProbeResult(probe=probe, target=target, source=ex.source, duration_ms=elapsed, **kw)


def _not_installed(code: int, program: str) -> str | None:
    if code == 127:
        return f"{program} is not installed where the probe ran"
    return None


# --- ping ---------------------------------------------------------------------------------

_SENT_RECV = re.compile(r"(\d+) packets transmitted, (\d+) (?:packets )?received")
_RTT_AVG = re.compile(r"= [\d.]+/([\d.]+)/")
_WIN_AVG = re.compile(r"Average = (\d+)ms")


def ping(
    host: str,
    *,
    count: int = 3,
    timeout: int = 2,
    executor: Executor | None = None,
    limiter: RateLimiter = DEFAULT_LIMITER,
) -> ProbeResult:
    """ICMP echo. ``ok`` if at least one real echo reply came back."""
    _host(host)
    _int(count, 1, 5, "count")
    _int(timeout, 1, 5, "timeout")
    ex = executor or LocalExecutor()
    if ex.platform == "win32":
        argv = ["ping", "-n", str(count), "-w", f"{timeout}000", host]
    elif ex.platform == "darwin":
        argv = ["ping", "-c", str(count), "-t", str(timeout), "-n", host]
    else:
        argv = ["ping", "-c", str(count), "-W", str(timeout), "-n", host]
    limiter.acquire()
    with _timed() as elapsed:
        code, out, err = ex.run(argv)
    if missing := _not_installed(code, "ping"):
        return _result("ping", host, ex, elapsed(), ok=False, summary=missing, error=missing)

    if ex.platform == "win32":
        # Count only real replies: "Destination host unreachable" lines have no TTL.
        received = sum(1 for line in out.splitlines() if "TTL=" in line.upper())
        avg = _WIN_AVG.search(out)
    else:
        m = _SENT_RECV.search(out)
        received = int(m.group(2)) if m else 0
        avg = _RTT_AVG.search(out)
    avg_ms = float(avg.group(1)) if avg and received else None
    data = {"sent": count, "received": received, "avg_rtt_ms": avg_ms}
    if received:
        summary = f"{received}/{count} replies from {host}, avg {avg_ms:g} ms"
    else:
        summary = f"no reply from {host} ({count} sent)"
        if err.strip():
            summary += f": {err.strip().splitlines()[-1][:200]}"
    return _result("ping", host, ex, elapsed(), ok=received > 0, summary=summary, data=data)


# --- traceroute ---------------------------------------------------------------------------

_HEADER_IP = re.compile(r"^(?:traceroute to \S+ \(([^)]+)\)|Tracing route to \S+ \[([^\]]+)\])")
_HOP = re.compile(r"^\s*(\d+)\s+(.*)$")
_IP_TOKEN = re.compile(r"^[0-9a-fA-F.:]+$")
_RTT = re.compile(r"<?([\d.]+)\s*ms")


def traceroute(
    host: str,
    *,
    max_hops: int = 20,
    executor: Executor | None = None,
    limiter: RateLimiter = DEFAULT_LIMITER,
) -> ProbeResult:
    """The routers on the path to ``host``. ``ok`` if the last hop is the destination."""
    _host(host)
    _int(max_hops, 1, 30, "max_hops")
    ex = executor or LocalExecutor()
    if ex.platform == "win32":
        argv = ["tracert", "-d", "-h", str(max_hops), "-w", "2000", host]
    else:
        argv = ["traceroute", "-n", "-q", "1", "-w", "2", "-m", str(max_hops), host]
    limiter.acquire()
    with _timed() as elapsed:
        code, out, err = ex.run(argv)
    if missing := _not_installed(code, argv[0]):
        return _result("traceroute", host, ex, elapsed(), ok=False, summary=missing, error=missing)

    dest = host
    hops: list[dict[str, Any]] = []
    for line in out.splitlines():
        if m := _HEADER_IP.match(line):
            dest = m.group(1) or m.group(2)
            continue
        m = _HOP.match(line)
        if not m:
            continue
        ips = [t for t in m.group(2).split() if _IP_TOKEN.match(t) and _is_ip(t)]
        rtt = _RTT.search(m.group(2))
        hops.append(
            {
                "hop": int(m.group(1)),
                "ip": ips[-1] if ips else None,
                "rtt_ms": float(rtt.group(1)) if rtt and ips else None,
            }
        )
    reached = bool(hops) and hops[-1]["ip"] == dest
    answered = [h for h in hops if h["ip"]]
    if reached:
        summary = f"reached {dest} in {len(hops)} hops"
    elif answered:
        last = answered[-1]
        summary = f"did not reach {dest}; last reply from hop {last['hop']} ({last['ip']})"
    else:
        summary = f"no hop answered on the way to {dest}"
        if err.strip():
            summary += f": {err.strip().splitlines()[-1][:200]}"
    data = {"destination": dest, "hops": hops}
    return _result("traceroute", host, ex, elapsed(), ok=reached, summary=summary, data=data)


def _is_ip(token: str) -> bool:
    try:
        ip_address(token)
    except ValueError:
        return False
    return True


# --- DNS ----------------------------------------------------------------------------------

_DIG_STATUS = re.compile(r"status: ([A-Z]+)")
_SINKHOLE = {"0.0.0.0", "::"}


def dns_resolve(
    name: str,
    *,
    record_type: str = "A",
    server: str | None = None,
    timeout: float = 3.0,
    executor: Executor | None = None,
    limiter: RateLimiter = DEFAULT_LIMITER,
) -> ProbeResult:
    """Look up ``name``, optionally asking one specific DNS server (an IP address).

    ``data["blocked_hint"]`` is set when the answer is 0.0.0.0 or ::, which is how
    Pi-hole and similar filters usually answer for blocked domains.
    """
    name = name.rstrip(".")
    if not _DNS_NAME.fullmatch(name):
        raise ValueError(f"not a valid DNS name: {name!r}")
    record_type = record_type.upper()
    if record_type not in RECORD_TYPES:
        raise ValueError(f"record_type must be one of {', '.join(RECORD_TYPES)}")
    if server is not None:
        server = str(ip_address(server))  # a resolver must be given as an IP
    if not 0.5 <= timeout <= 10:
        raise ValueError("timeout must be between 0.5 and 10 seconds")
    ex = executor or LocalExecutor()
    target = f"{name} {record_type}"
    limiter.acquire()
    with _timed() as elapsed:
        if ex.remote:
            status, answers, used, error = _dig(ex, name, record_type, server)
        else:
            status, answers, used, error = _dns_local(name, record_type, server, timeout)
    via = used or server or "the system resolver"
    blocked = any(a in _SINKHOLE for a in answers)
    data = {
        "status": status,
        "answers": answers,
        "server": used or server,
        "blocked_hint": blocked,
    }
    ok = status == "NOERROR" and bool(answers)
    if ok:
        summary = f"{name} {record_type} -> {', '.join(answers)} (via {via})"
        if blocked:
            summary += "; looks blocked by a DNS filter"
    elif status == "NOERROR":
        summary = f"{name} has no {record_type} record (via {via})"
    else:
        summary = f"{name} {record_type}: {status} (via {via})"
    return _result("dns", target, ex, elapsed(), ok=ok, summary=summary, data=data, error=error)


def _dns_local(
    name: str, rtype: str, server: str | None, timeout: float
) -> tuple[str, list[str], str | None, str | None]:
    try:
        resolver = dns.resolver.Resolver(configure=server is None)
    except dns.resolver.NoResolverConfiguration as exc:
        return "NO_RESOLVER", [], None, str(exc)
    if server:
        resolver.nameservers = [server]
    resolver.lifetime = timeout
    try:
        answer = resolver.resolve(name, rtype, raise_on_no_answer=False, search=False)
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN", [], server, None
    except dns.resolver.NoNameservers as exc:
        return "SERVFAIL", [], server, str(exc)[:300]
    except dns.exception.Timeout:
        return "TIMEOUT", [], server, None
    except dns.exception.DNSException as exc:
        return "ERROR", [], server, str(exc)[:300]
    answers = [r.to_text() for r in answer.rrset] if answer.rrset is not None else []
    return "NOERROR", answers, getattr(answer, "nameserver", None) or server, None


def _dig(
    ex: Executor, name: str, rtype: str, server: str | None
) -> tuple[str, list[str], str | None, str | None]:
    argv = ["dig", "+time=2", "+tries=1", "+noall", "+comments", "+answer"]
    if server:
        argv.append(f"@{server}")
    argv += [name, rtype]
    code, out, err = ex.run(argv)
    if missing := _not_installed(code, "dig"):
        return "ERROR", [], server, missing + " (install dnsutils / bind-utils)"
    if code == 9 or "timed out" in (out + err):
        return "TIMEOUT", [], server, None
    m = _DIG_STATUS.search(out)
    if not m:
        return "ERROR", [], server, (err or out).strip()[:300] or f"dig exited {code}"
    answers = []
    for line in out.splitlines():
        if not line.strip() or line.startswith(";"):
            continue
        fields = line.split(None, 4)
        if len(fields) == 5 and fields[3] == rtype:
            answers.append(fields[4].strip())
    return m.group(1), answers, server, None


# --- TCP ----------------------------------------------------------------------------------


def tcp_connect(
    host: str,
    port: int,
    *,
    timeout: int = 3,
    executor: Executor | None = None,
    limiter: RateLimiter = DEFAULT_LIMITER,
) -> ProbeResult:
    """Open a TCP connection and close it at once (no data sent). ``ok`` if it opened."""
    _host(host)
    _int(port, 1, 65535, "port")
    _int(timeout, 1, 9, "timeout")
    ex = executor or LocalExecutor()
    target = f"{host}:{port}"
    limiter.acquire()
    with _timed() as elapsed:
        if ex.remote:
            code, out, err = ex.run(["nc", "-z", "-w", str(timeout), host, str(port)])
            if missing := _not_installed(code, "nc"):
                return _result(
                    "tcp", target, ex, elapsed(), ok=False, summary=missing, error=missing
                )
            text = (out + err).lower()
            if code == 0:
                state = "open"
            elif "refused" in text:
                state = "refused"
            elif "timed out" in text or "timeout" in text:
                state = "timeout"
            elif "resolve" in text or "name or service" in text:
                state = "unresolved"
            else:
                state = "closed_or_filtered"
        else:
            state = _tcp_local(host, port, timeout)
    summaries = {
        "open": f"{target} is open",
        "refused": f"{target} refused the connection (host is up, nothing listening)",
        "timeout": f"{target} timed out (filtered by a firewall, or host down)",
        "unresolved": f"{host} could not be resolved",
        "closed_or_filtered": f"{target} is closed or filtered",
        "unreachable": f"no route to {host}",
    }
    return _result(
        "tcp",
        target,
        ex,
        elapsed(),
        ok=state == "open",
        summary=summaries.get(state, f"{target}: {state}"),
        data={"state": state},
    )


def _tcp_local(host: str, port: int, timeout: int) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "refused"
    except TimeoutError:
        return "timeout"
    except socket.gaierror:
        return "unresolved"
    except OSError as exc:
        return "unreachable" if "unreachable" in str(exc).lower() else "closed_or_filtered"


# --- HTTP ---------------------------------------------------------------------------------


def _head_only(request: httpx.Request) -> None:
    if request.method != "HEAD":
        raise ReadOnlyViolation(f"http probe refused {request.method}")


def http_head(
    url: str,
    *,
    timeout: int = 5,
    verify_tls: bool = True,
    executor: Executor | None = None,
    limiter: RateLimiter = DEFAULT_LIMITER,
    _transport: httpx.BaseTransport | None = None,
) -> ProbeResult:
    """Send one HEAD request (redirects are reported, not followed). ``ok`` on any HTTP reply."""
    ex = executor or LocalExecutor()
    _url(url, remote=ex.remote)
    _int(timeout, 1, 30, "timeout")
    limiter.acquire()
    with _timed() as elapsed:
        if ex.remote:
            data, error = _curl_head(ex, url, timeout)
        else:
            data, error = _httpx_head(url, timeout, verify_tls, _transport)
    status = data.get("status_code")
    if status is not None:
        summary = f"HTTP {status} from {url}"
        if data.get("location"):
            summary += f" -> {data['location']}"
        if data.get("server"):
            summary += f" (server: {data['server']})"
    else:
        summary = f"no HTTP response from {url}: {error}"
    return _result(
        "http", url, ex, elapsed(), ok=status is not None, summary=summary, data=data, error=error
    )


def _httpx_head(
    url: str, timeout: int, verify: bool, transport: httpx.BaseTransport | None
) -> tuple[dict[str, Any], str | None]:
    try:
        with httpx.Client(
            timeout=timeout,
            verify=verify,
            follow_redirects=False,
            transport=transport,
            event_hooks={"request": [_head_only]},
        ) as client:
            resp = client.head(url)
    except httpx.ConnectError as exc:
        text = str(exc)
        if "CERTIFICATE_VERIFY_FAILED" in text or "certificate" in text.lower():
            return {"state": "tls_error"}, f"TLS certificate not trusted: {text[:200]}"
        return {"state": "connect_error"}, text[:300] or "connection failed"
    except httpx.TimeoutException:
        return {"state": "timeout"}, f"timed out after {timeout}s"
    except httpx.HTTPError as exc:
        return {"state": "error"}, str(exc)[:300]
    return {
        "state": "response",
        "status_code": resp.status_code,
        "http_version": resp.http_version,
        "server": resp.headers.get("server"),
        "location": resp.headers.get("location"),
    }, None


def _curl_head(ex: Executor, url: str, timeout: int) -> tuple[dict[str, Any], str | None]:
    code, out, err = ex.run(["curl", "-sS", "-I", "-m", str(timeout), url])
    if missing := _not_installed(code, "curl"):
        return {"state": "error"}, missing
    if code != 0:
        state = "timeout" if code == 28 else "tls_error" if code == 60 else "connect_error"
        return {"state": state}, err.strip()[:300] or f"curl exited {code}"
    headers: dict[str, str] = {}
    status_line = ""
    for line in out.splitlines():
        line = line.strip()
        if line.upper().startswith("HTTP/"):
            status_line, headers = line, {}  # keep only the last response
        elif ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()
    parts = status_line.split()
    if len(parts) < 2 or not parts[1].isdigit():
        return {"state": "error"}, "no HTTP status line in curl output"
    return {
        "state": "response",
        "status_code": int(parts[1]),
        "http_version": parts[0],
        "server": headers.get("server"),
        "location": headers.get("location"),
    }, None
