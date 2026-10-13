from __future__ import annotations

import json
import logging
from ipaddress import ip_address, ip_network
from pathlib import Path

import httpx
import pytest

from labwarden.collectors import ReadOnlyViolation
from labwarden.collectors.docker import (
    DockerCollector,
    DockerError,
    DockerOptions,
    _guard_request,
)

FIXTURES = Path(__file__).parent / "fixtures" / "docker"


def _load(name: str) -> object:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class FakeProxy:
    """Behaves like docker-socket-proxy: serves fixtures, 403s for disabled sections."""

    def __init__(self, blocked: tuple[str, ...] = ()) -> None:
        self.blocked = blocked
        self.requests: list[tuple[str, str]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.requests.append((request.method, path))
        if any(path.startswith(prefix) for prefix in self.blocked):
            return httpx.Response(403, text="Forbidden")
        if path == "/containers/json":
            assert request.url.params.get("all") == "1"
            return httpx.Response(200, json=_load("containers.json"))
        if path.startswith("/containers/") and path.endswith("/json"):
            cid = path.split("/")[2]
            return httpx.Response(200, json=_load(f"inspect_{cid}.json"))
        if path == "/networks":
            return httpx.Response(200, json=_load("networks.json"))
        if path == "/version":
            return httpx.Response(200, json=_load("version.json"))
        return httpx.Response(404)


def _collector(fake: FakeProxy) -> DockerCollector:
    opts = DockerOptions(url="tcp://192.168.20.10:2375")
    collector = DockerCollector("docker-server", opts, Path("."))
    collector._transport = httpx.MockTransport(fake)
    return collector


def test_containers_are_mapped() -> None:
    model = _collector(FakeProxy()).collect()
    by_name = {c.name: c for c in model.containers}
    assert sorted(by_name) == ["cadvisor", "dockerproxy", "jellyfin", "old-db"]
    assert all(c.host == "docker-server" for c in model.containers)

    jellyfin = by_name["jellyfin"]
    assert jellyfin.image == "jellyfin/jellyfin:10.9.11"
    assert jellyfin.state == "running"
    assert jellyfin.networks == ["media"]
    assert jellyfin.user == "1000:1000"
    assert jellyfin.restart_policy == "unless-stopped"
    assert not jellyfin.privileged
    published = [(str(p.host_ip), p.host_port) for p in jellyfin.ports if p.host_port]
    assert published == [("0.0.0.0", 8096), ("::", 8096)]
    # 8920 is exposed by the image but not published.
    assert [(p.container_port, p.host_port) for p in jellyfin.ports if not p.host_port] == [
        (8920, None)
    ]
    assert all(p.is_exposed_on_all_interfaces() for p in jellyfin.ports if p.host_port)

    cadvisor = by_name["cadvisor"]
    assert cadvisor.privileged
    assert cadvisor.user is None  # image default, i.e. root
    assert cadvisor.networks == ["host"]


def test_stopped_container_keeps_its_configured_ports() -> None:
    model = _collector(FakeProxy()).collect()
    old_db = next(c for c in model.containers if c.name == "old-db")
    assert old_db.state == "exited"
    assert old_db.restart_policy == "no"
    assert [(p.container_port, p.host_ip, p.host_port) for p in old_db.ports] == [
        (5432, None, 5432)
    ]


def test_services_are_only_running_published_ports() -> None:
    model = _collector(FakeProxy()).collect()
    services = {(str(s.address), s.port, s.process) for s in model.services}
    assert services == {
        ("0.0.0.0", 8096, "docker:jellyfin"),
        ("::", 8096, "docker:jellyfin"),
        ("127.0.0.1", 2375, "docker:dockerproxy"),
    }
    assert all(s.device == "docker-server" for s in model.services)


def test_networks_become_subnets() -> None:
    model = _collector(FakeProxy()).collect()
    subnets = {s.name: s for s in model.subnets}
    assert sorted(subnets) == [
        "docker:docker-server/bridge",
        "docker:docker-server/labwarden",
        "docker:docker-server/media",
    ]
    assert subnets["docker:docker-server/media"].cidr == ip_network("172.20.0.0/16")
    assert subnets["docker:docker-server/media"].gateway == ip_address("172.20.0.1")
    assert subnets["docker:docker-server/labwarden"].gateway is None


def test_host_device_from_version() -> None:
    model = _collector(FakeProxy()).collect()
    (host,) = model.devices
    assert host.name == "docker-server"
    assert host.os == "Docker 27.3.1 (linux/amd64)"
    assert host.roles == ["docker"]


def test_env_and_labels_never_reach_the_model() -> None:
    model = _collector(FakeProxy()).collect()
    dumped = model.model_dump_json()
    assert "FIXTURE-SECRET-DO-NOT-LEAK" not in dumped
    assert "POSTGRES_PASSWORD" not in dumped


def test_only_get_requests_are_sent() -> None:
    fake = FakeProxy()
    _collector(fake).collect()
    assert {m for m, _ in fake.requests} == {"GET"}


def test_optional_sections_can_be_blocked(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        model = _collector(FakeProxy(blocked=("/networks", "/version"))).collect()
    assert len(model.containers) == 4
    assert model.subnets == [] and model.devices == []
    assert "NETWORKS=1" in caplog.text


def test_blocked_containers_is_an_error() -> None:
    with pytest.raises(DockerError, match="CONTAINERS=1"):
        _collector(FakeProxy(blocked=("/containers",))).collect()


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/containers/aaa111/stop"),
        ("POST", "/containers/aaa111/exec"),
        ("DELETE", "/containers/aaa111"),
        ("POST", "/networks/create"),
        ("PUT", "/containers/aaa111/archive"),
    ],
)
def test_guard_refuses_writes(method: str, path: str) -> None:
    with pytest.raises(ReadOnlyViolation):
        _guard_request(httpx.Request(method, f"http://192.168.20.10:2375{path}"))


def test_url_forms() -> None:
    assert DockerOptions(url="tcp://10.0.0.5:2375").url == "http://10.0.0.5:2375"
    assert DockerOptions(url="https://docker.lan:2376/").url == "https://docker.lan:2376"


@pytest.mark.parametrize(
    "url", ["unix:///var/run/docker.sock", "10.0.0.5:2375", "http://host:2375/v1.47"]
)
def test_bad_urls_are_rejected(url: str) -> None:
    with pytest.raises(ValueError):
        DockerOptions(url=url)
