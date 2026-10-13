"""LabWarden as an MCP server: every ``LabToolkit`` tool, plus a summary resource.

Run it with ``labwarden mcp`` (stdio), and point Claude Desktop, Claude Code
or any other MCP client at it. See ``docs/mcp.md``.

Every tool is annotated ``read_only_hint=True, destructive_hint=False``.
``tests/test_mcp_server.py`` fails if a tool name contains a mutating verb, or
if any tool is registered that isn't in ``labwarden.toolkit.TOOLS``.
"""

from __future__ import annotations

import json

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from labwarden import __version__
from labwarden.config import Config
from labwarden.toolkit import TOOLS, LabToolkit

INSTRUCTIONS = """\
LabWarden is a read-only view of a homelab network: devices, addresses, subnets,
routes, DNS, Docker containers, listening services and firewall rules, collected
into snapshots, plus live network probes.

How to work:
1. Call lab_summary first. It lists devices, what each collector covers, which
   targets failed, and blind spots (things nobody collects).
2. Use the inventory tools for stored facts. Snapshots can be stale; check
   age_minutes before relying on them.
3. Use the probe_* tools to test hypotheses live. Probes can run from a Linux
   host with from_host, to see the network from that machine's point of view.
4. Cite the tool output that proves each conclusion.

LabWarden can't change anything. To fix a problem, tell the user exactly what to
change, where, how to roll it back, and how to verify it (e.g. by re-running a probe).
"""

#: Inventory tools only read stored snapshots, so repeated calls are harmless and
#: touch nothing outside LabWarden. Probes send packets on the real network.
_ANNOTATIONS = {
    "inventory": ToolAnnotations(
        read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False
    ),
    "probe": ToolAnnotations(
        read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=True
    ),
}


def build_server(config: Config, toolkit: LabToolkit | None = None) -> MCPServer:
    toolkit = toolkit or LabToolkit(config)
    server = MCPServer(
        name="labwarden",
        title="LabWarden",
        description="Read-only AI network & security engineer for your homelab.",
        instructions=INSTRUCTIONS,
        version=__version__,
    )
    tools = toolkit.callables()
    for spec in TOOLS:
        server.add_tool(tools[spec.name], name=spec.name, annotations=_ANNOTATIONS[spec.kind])

    @server.resource(
        "labwarden://summary",
        name="lab_summary",
        description="Overview of the lab from the latest snapshot (same as the lab_summary tool).",
        mime_type="application/json",
    )
    def summary_resource() -> str:
        return json.dumps(toolkit.lab_summary(), indent=2)

    return server
