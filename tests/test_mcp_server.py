from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.mcpserver.exceptions import ToolError as McpToolError

from labwarden.config import load_config
from labwarden.mcp_server import build_server
from labwarden.model.entities import (
    Address,
    Container,
    Device,
    FirewallRule,
    PortMapping,
    Route,
    Service,
    Subnet,
)
from labwarden.model.lab import LabModel
from labwarden.model.store import SnapshotStore
from labwarden.probes import RateLimiter
from labwarden.toolkit import TOOLS, LabToolkit, ToolError

CONFIG = """
data_dir: data
targets:
  - name: inventory
    plugin: manual
    options: {file: inventory.yaml}
  - name: pihole
    plugin: pihole
    options: {url: "http://192.168.20.2", password: "SUPERSECRET-DO-NOT-LEAK"}
  - name: docker-server-host
    plugin: linux_ssh
    options: {host: 192.168.20.10, key_file: id_ed25519}
"""

#: Verbs that would suggest a tool changes something. No tool name may contain one.
MUTATING_VERBS = {
    "add", "apply", "block", "change", "create", "delete", "deploy", "disable", "drop",
    "edit", "enable", "exec", "execute", "flush", "install", "kill", "modify", "patch",
    "post", "push", "put", "reboot", "remove", "reset", "restart", "run", "set", "shutdown",
    "start", "stop", "update", "upgrade", "write",
}  # fmt: skip


def _model(nas_ip: str) -> LabModel:
    return LabModel(
        devices=[
            Device(name="pihole", kind="server", management_ip="192.168.20.2", roles=["dns"]),
            Device(name="pihole.lan", kind="other", management_ip="192.168.20.2"),
            Device(name="docker-server", kind="server", management_ip="192.168.20.10"),
            Device(name="nas", kind="nas", management_ip=nas_ip),
        ],
        addresses=[
            Address(device="docker-server", interface="enp1s0.20", address="192.168.20.10/24"),
        ],
        subnets=[Subnet(cidr="192.168.20.0/24", gateway="192.168.20.1", vlan_id=20)],
        routes=[Route(device="docker-server", destination="0.0.0.0/0", gateway="192.168.20.1")],
        containers=[
            Container(
                host="docker-server",
                name="jellyfin",
                image="jellyfin/jellyfin:10.9.11",
                state="running",
                user="1000:1000",
                ports=[PortMapping(container_port=8096, host_port=8096)],
            ),
            Container(
                host="docker-server",
                name="dockerproxy",
                image="tecnativa/docker-socket-proxy:0.3.0",
                state="running",
                ports=[PortMapping(container_port=2375, host_ip="127.0.0.1", host_port=2375)],
            ),
        ],
        services=[
            Service(device="docker-server", address="0.0.0.0", port=22, process="sshd"),
            Service(
                device="docker-server", address="0.0.0.0", port=8096, process="docker:jellyfin"
            ),
        ],
        firewall_rules=[
            FirewallRule(
                device="docker-server", chain="inet filter input", order=0, action="block",
                description="default policy",
            ),
        ],
    )  # fmt: skip


@pytest.fixture
def lab(tmp_path: Path) -> Path:
    (tmp_path / "labwarden.yaml").write_text(CONFIG, encoding="utf-8")
    (tmp_path / "inventory.yaml").write_text("devices: []\n", encoding="utf-8")
    config = load_config(tmp_path / "labwarden.yaml")
    store = SnapshotStore(config.snapshot_db)
    yesterday = datetime.now(UTC) - timedelta(days=1)
    store.save(_model("192.168.20.20"), label="before", taken_at=yesterday)
    store.save(
        _model("192.168.20.21"),
        label="after",
        errors={"pihole": "PiholeError: rejected"},
        taken_at=yesterday + timedelta(hours=23),
    )
    return tmp_path


@pytest.fixture
def toolkit(lab: Path) -> LabToolkit:
    return LabToolkit(load_config(lab / "labwarden.yaml"), limiter=RateLimiter(1000, 1000))


def call(server, name: str, args: dict | None = None) -> dict:
    result = asyncio.run(server.call_tool(name, args or {}))
    assert not result.is_error, result
    return json.loads(result.content[0].text)


# --- the tool surface ---------------------------------------------------------------------


def test_registered_tools_are_exactly_the_toolkit(lab: Path) -> None:
    server = build_server(load_config(lab / "labwarden.yaml"))
    tools = asyncio.run(server.list_tools())
    assert [t.name for t in tools] == [spec.name for spec in TOOLS]


def test_no_tool_name_contains_a_mutating_verb() -> None:
    for spec in TOOLS:
        words = set(spec.name.split("_"))
        assert not words & MUTATING_VERBS, spec.name


def test_every_tool_is_annotated_read_only(lab: Path) -> None:
    server = build_server(load_config(lab / "labwarden.yaml"))
    kinds = {spec.name: spec.kind for spec in TOOLS}
    for tool in asyncio.run(server.list_tools()):
        a = tool.annotations
        assert a.read_only_hint is True and a.destructive_hint is False, tool.name
        assert a.open_world_hint is (kinds[tool.name] == "probe"), tool.name


def test_every_tool_and_parameter_is_described_for_the_model(lab: Path) -> None:
    server = build_server(load_config(lab / "labwarden.yaml"))
    for tool in asyncio.run(server.list_tools()):
        assert tool.description and len(tool.description) > 40, tool.name
        for param, schema in tool.input_schema.get("properties", {}).items():
            assert schema.get("description"), f"{tool.name}.{param} has no description"


# --- inventory tools ----------------------------------------------------------------------


def test_lab_summary(toolkit: LabToolkit) -> None:
    s = toolkit.lab_summary()
    assert s["snapshot_id"] == 2 and s["age_minutes"] > 0
    assert s["failed_targets"] == {"pihole": "PiholeError: rejected"}
    assert s["probe_sources"] == ["docker-server-host"]
    # The manual inventory "provides" everything but observes nothing.
    assert "containers" in s["blind_spots"]  # no docker target configured
    assert "dns_records" not in s["blind_spots"]  # pihole provides it
    assert {t["name"] for t in s["targets"]} == {"inventory", "pihole", "docker-server-host"}


def test_credentials_never_reach_the_model(lab: Path) -> None:
    server = build_server(load_config(lab / "labwarden.yaml"))
    for spec in TOOLS:
        if spec.kind != "inventory":
            continue
        args = {"query": "e"} if spec.name == "inventory_search" else {}
        if spec.name == "device_get":
            args = {"name_or_ip": "pihole"}
        result = asyncio.run(server.call_tool(spec.name, args))
        assert "SUPERSECRET" not in result.content[0].text, spec.name


def test_device_get_by_ip_finds_every_name_for_the_same_box(toolkit: LabToolkit) -> None:
    names = [d["device"]["name"] for d in toolkit.device_get("192.168.20.2")["devices"]]
    assert names == ["pihole", "pihole.lan"]


def test_device_get_collects_related_facts(toolkit: LabToolkit) -> None:
    (view,) = toolkit.device_get("docker-server")["devices"]
    assert [c["name"] for c in view["containers"]] == ["jellyfin", "dockerproxy"]
    assert {s["port"] for s in view["services"]} == {22, 8096}
    assert view["routes"][0]["gateway"] == "192.168.20.1"
    assert view["firewall_rules"][0]["description"] == "default policy"


def test_device_get_unknown_suggests_similar_names(toolkit: LabToolkit) -> None:
    with pytest.raises(ToolError, match=r"Similar names: pihole, pihole\.lan"):
        toolkit.device_get("pihol")


def test_inventory_search(toolkit: LabToolkit) -> None:
    hits = toolkit.inventory_search("jellyfin")
    assert {h["kind"] for h in hits["results"]} == {"containers", "services"}
    assert toolkit.inventory_search("jellyfin", kind="services")["count"] == 1
    assert toolkit.inventory_search("192.168.20", limit=2)["truncated"] is True
    with pytest.raises(ToolError, match="unknown kind"):
        toolkit.inventory_search("x", kind="nope")


def test_docker_containers_flags_exposure_and_root(toolkit: LabToolkit) -> None:
    containers = {c["name"]: c for c in toolkit.docker_containers()["containers"]}
    assert containers["jellyfin"]["exposed_ports"] == [8096]
    assert containers["jellyfin"]["runs_as_root"] is False
    assert containers["dockerproxy"]["exposed_ports"] == []  # bound to 127.0.0.1 only
    assert containers["dockerproxy"]["runs_as_root"] is True
    exposed = toolkit.docker_containers(exposed_only=True)["containers"]
    assert [c["name"] for c in exposed] == ["jellyfin"]


def test_services_and_subnets(toolkit: LabToolkit) -> None:
    assert toolkit.services_list(port=22)["services"][0]["process"] == "sshd"
    assert toolkit.network_subnets()["subnets"][0]["vlan_id"] == 20


def test_snapshot_diff_defaults_to_the_last_two(toolkit: LabToolkit) -> None:
    diff = toolkit.snapshot_diff()
    assert (diff["before"], diff["after"]) == (1, 2)
    (change,) = diff["changes"]
    assert change["status"] == "changed" and change["key"] == "nas"
    assert change["fields"] == [
        {"field": "management_ip", "before": "192.168.20.20", "after": "192.168.20.21"}
    ]
    assert [s["label"] for s in toolkit.snapshot_list()["snapshots"]] == ["after", "before"]


def test_no_snapshots_is_a_clear_error(tmp_path: Path) -> None:
    (tmp_path / "labwarden.yaml").write_text("data_dir: data\n", encoding="utf-8")
    toolkit = LabToolkit(load_config(tmp_path / "labwarden.yaml"))
    with pytest.raises(ToolError, match="labwarden collect"):
        toolkit.lab_summary()


# --- probes and errors through MCP --------------------------------------------------------


def test_probe_tool_runs_a_live_local_probe(lab: Path) -> None:
    server = build_server(load_config(lab / "labwarden.yaml"))
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        result = call(server, "probe_tcp", {"host": "127.0.0.1", "port": port})
    assert result["ok"] is True and result["data"]["state"] == "open"


@pytest.mark.parametrize(
    ("tool", "args", "message"),
    [
        ("probe_ping", {"host": "1.1.1.1", "from_host": "pihole"}, "only run from linux_ssh"),
        ("probe_ping", {"host": "-oProxyCommand=sh"}, "invalid input"),
        ("probe_tcp", {"host": "nas.lan", "port": 70000}, "less than or equal"),
        ("device_get", {"name_or_ip": "nope"}, "No device"),
    ],
)
def test_errors_reach_the_model_with_their_reason(lab: Path, tool, args, message) -> None:
    server = build_server(load_config(lab / "labwarden.yaml"))
    with pytest.raises(McpToolError, match=message):
        asyncio.run(server.call_tool(tool, args))


def test_summary_resource(lab: Path) -> None:
    server = build_server(load_config(lab / "labwarden.yaml"))
    contents = asyncio.run(server.read_resource("labwarden://summary"))
    text = next(iter(contents)).content
    assert json.loads(text)["snapshot_id"] == 2


# --- end to end over stdio ----------------------------------------------------------------


def test_stdio_end_to_end(lab: Path) -> None:
    """Start `labwarden mcp` as a real subprocess and talk MCP to it."""

    async def session_run() -> tuple[list[str], dict, str | None]:
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "labwarden.cli", "mcp", "--config", str(lab / "labwarden.yaml")],
            env=dict(os.environ),
        )
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            result = await session.call_tool("device_get", {"name_or_ip": "nas"})
            return (
                [t.name for t in tools.tools],
                json.loads(result.content[0].text),
                session.instructions,
            )

    names, nas, instructions = asyncio.run(asyncio.wait_for(session_run(), timeout=60))
    assert names == [spec.name for spec in TOOLS]
    assert nas["devices"][0]["device"]["management_ip"] == "192.168.20.21"
    assert instructions and "lab_summary first" in instructions
