from __future__ import annotations

import json
import logging
from ipaddress import ip_interface, ip_network
from pathlib import Path

import httpx
import pytest

from labwarden.collectors import ReadOnlyViolation
from labwarden.collectors.pihole import (
    PiholeCollector,
    PiholeError,
    PiholeOptions,
    _guard_request,
)

FIXTURES = Path(__file__).parent / "fixtures" / "pihole"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class FakePihole:
    """Serves the fixtures and records every request the collector makes."""

    def __init__(self, auth: str = "auth_ok.json", config: dict | None = None) -> None:
        self.auth = auth
        self.config = config or _load("config.json")
        self.requests: list[tuple[str, str, str | None]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        sid = request.headers.get("X-FTL-SID")
        self.requests.append((request.method, request.url.path, sid))
        if request.url.path == "/api/auth":
            if request.method == "DELETE":
                return httpx.Response(204)
            body = _load(self.auth)
            return httpx.Response(200 if body["session"]["valid"] else 401, json=body)
        if sid != "TEST-SID":
            return httpx.Response(401, json={"error": {"key": "unauthorized"}})
        routes = {
            "/api/config": self.config,
            "/api/dhcp/leases": _load("leases.json"),
            "/api/info/version": _load("version.json"),
        }
        if request.url.path not in routes:
            return httpx.Response(404)
        return httpx.Response(200, json=routes[request.url.path])


def _collector(fake: FakePihole, **options: object) -> PiholeCollector:
    opts = PiholeOptions.model_validate(
        {"url": "http://192.168.1.2", "password": "secret", **options}
    )
    collector = PiholeCollector("pihole", opts, Path("."))
    collector._transport = httpx.MockTransport(fake)
    return collector


def test_collect_maps_pihole_into_lab_model() -> None:
    model = _collector(FakePihole()).collect()

    pihole = model.device("pihole")
    assert pihole is not None
    assert str(pihole.management_ip) == "192.168.1.2"
    assert pihole.roles == ["dns", "dhcp"]
    assert pihole.os == "Pi-hole (core v6.1, FTL v6.1)"
    assert pihole.tags == ["dns-upstream:1.1.1.1", "dns-upstream:9.9.9.9#53", "dns-domain:lan"]

    records = {(r.name, r.type, r.value) for r in model.dns_records}
    assert records == {
        ("docker.lan", "A", "192.168.1.10"),
        ("docker", "A", "192.168.1.10"),
        ("nas.lan", "A", "192.168.1.20"),
        ("nas.lan", "AAAA", "fd00::20"),
        ("jellyfin.lan", "CNAME", "docker.lan"),
        ("grafana.lan", "CNAME", "docker.lan"),
        ("git.lan", "CNAME", "docker.lan"),
    }
    assert all(r.server == "pihole" for r in model.dns_records)

    (scope,) = model.dhcp_scopes
    # netmask 0.0.0.0 means "from the interface"; the range fits a /24.
    assert scope.subnet == ip_network("192.168.1.0/24")
    assert str(scope.gateway) == "192.168.1.1"
    assert [str(d) for d in scope.dns_servers] == ["192.168.1.2"]
    assert [str(s.cidr) for s in model.subnets] == ["192.168.1.0/24"]


def test_leases_become_client_devices() -> None:
    model = _collector(FakePihole()).collect()

    clients = {d.name for d in model.devices if d.kind == "client"}
    # Nameless lease falls back to the MAC; the Pi-hole's own lease is not a client.
    assert clients == {"laptop", "dhcp-0200000000ab"}
    addresses = {a.device: a.address for a in model.addresses}
    assert addresses == {
        "laptop": ip_interface("192.168.1.101/24"),
        "dhcp-0200000000ab": ip_interface("192.168.1.150/24"),
    }
    assert all(a.dhcp for a in model.addresses)


def test_session_is_used_and_closed() -> None:
    fake = FakePihole()
    _collector(fake).collect()

    assert fake.requests[0] == ("POST", "/api/auth", None)
    assert fake.requests[-1] == ("DELETE", "/api/auth", "TEST-SID")
    gets = [r for r in fake.requests if r[0] == "GET"]
    assert gets and all(sid == "TEST-SID" for _, _, sid in gets)
    assert {m for m, _, _ in fake.requests} == {"GET", "POST", "DELETE"}


def test_wrong_password_is_reported_without_the_password() -> None:
    with pytest.raises(PiholeError, match="rejected the password") as exc:
        _collector(FakePihole(auth="auth_bad.json")).collect()
    assert "secret" not in str(exc.value)


def test_missing_password_is_explained() -> None:
    fake = FakePihole()
    with pytest.raises(PiholeError, match="requires a password"):
        _collector(fake, password=None).collect()
    assert fake.requests[0][0] == "GET"  # no login attempted, so no logout either
    assert all(m == "GET" for m, _, _ in fake.requests)


def test_app_sudo_warns(caplog: pytest.LogCaptureFixture) -> None:
    config = _load("config.json")
    config["config"]["webserver"]["api"]["app_sudo"] = True
    with caplog.at_level(logging.WARNING):
        _collector(FakePihole(config=config)).collect()
    assert "app_sudo" in caplog.text


def test_dhcp_off_and_legacy_domain() -> None:
    config = _load("config.json")
    config["config"]["dhcp"]["active"] = False
    config["config"]["dns"]["domain"] = "home.arpa"  # v6.0 used a plain string
    model = _collector(FakePihole(config=config)).collect()

    pihole = model.device("pihole")
    assert pihole is not None
    assert pihole.roles == ["dns"]
    assert "dns-domain:home.arpa" in pihole.tags
    assert model.dhcp_scopes == [] and model.subnets == []


def test_explicit_netmask_is_used() -> None:
    config = _load("config.json")
    config["config"]["dhcp"]["netmask"] = "255.255.254.0"
    model = _collector(FakePihole(config=config)).collect()
    assert model.dhcp_scopes[0].subnet == ip_network("192.168.0.0/23")


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/api/config"),
        ("PUT", "/api/config/dns/hosts"),
        ("DELETE", "/api/dhcp/leases"),
        ("PATCH", "/api/config"),
        ("POST", "/api/action/restartdns"),
        ("POST", "/api/auth/extra"),
    ],
)
def test_guard_refuses_writes(method: str, path: str) -> None:
    with pytest.raises(ReadOnlyViolation):
        _guard_request(httpx.Request(method, f"http://192.168.1.2{path}"))


@pytest.mark.parametrize(
    ("method", "path"),
    [("GET", "/api/config"), ("POST", "/api/auth"), ("DELETE", "/api/auth")],
)
def test_guard_allows_reads_and_session(method: str, path: str) -> None:
    _guard_request(httpx.Request(method, f"http://192.168.1.2{path}"))


@pytest.mark.parametrize("url", ["192.168.1.2", "ftp://pi.hole", "http://pi.hole/admin"])
def test_bad_urls_are_rejected(url: str) -> None:
    with pytest.raises(ValueError):
        PiholeOptions(url=url)


def test_url_trailing_slash_is_normalized() -> None:
    assert PiholeOptions(url="https://pi.hole:8443/").url == "https://pi.hole:8443"
