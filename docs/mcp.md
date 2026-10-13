# Using LabWarden from Claude (MCP)

`labwarden mcp` runs an [MCP](https://modelcontextprotocol.io) server over stdio.
Any MCP client (Claude Desktop, Claude Code, ...) then gets LabWarden's
read-only tools. You ask questions in plain language, and Claude looks up the
inventory and runs probes to answer them.

## Before you start

1. Have a working `labwarden.yaml` (copy `examples/labwarden.yaml`).
2. Take at least one snapshot: `uv run labwarden collect`. The inventory tools
   read the latest snapshot, so collect again whenever the lab changes.

## Claude Code

From the repo directory:

```sh
claude mcp add labwarden -- uv --directory /path/to/labwarden run labwarden mcp --config /path/to/labwarden.yaml
```

Add `-s user` to make it available in every project. Check it with `claude mcp list`.

## Claude Desktop

Edit the config file:
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "labwarden": {
      "command": "uv",
      "args": [
        "--directory", "D:/CodeProjects/AI_Home_NetSecEngineer",
        "run", "labwarden", "mcp",
        "--config", "D:/CodeProjects/AI_Home_NetSecEngineer/labwarden.yaml"
      ]
    }
  }
}
```

If Claude Desktop can't find `uv`, use its full path as `command`. On
Windows, that's the output of `where uv`. Restart Claude Desktop afterwards.

## What Claude gets

| Tool | What it does |
|---|---|
| `lab_summary` | Start here: devices, collectors, failed targets, snapshot age, **blind spots** |
| `inventory_search` | Find any entity mentioning a name, IP, MAC, image, port... |
| `device_get` | One device with its interfaces, addresses, routes, services, containers, firewall rules (by name or IP) |
| `network_subnets` | Subnets, VLANs, DHCP scopes |
| `routes_get` | Routing tables |
| `dns_records` | Local DNS records (e.g. Pi-hole local DNS) |
| `docker_containers` | Containers, with `exposed_ports` and `runs_as_root` flags |
| `services_list` | Listening sockets ("what listens on 445?") |
| `firewall_rules` | Firewall rules in evaluation order |
| `snapshot_list`, `snapshot_diff` | History, and "what changed since yesterday?" |
| `probe_ping`, `probe_traceroute`, `probe_dns`, `probe_tcp`, `probe_http` | Live, rate-limited probes. Add `from_host` to run one from a `linux_ssh` host. |

There's also a `labwarden://summary` resource with the same content as `lab_summary`.

All tools are annotated read-only and non-destructive. None of them can change
anything; see the "Read-only by design" section of the README. Probe tools are
marked *open-world*, because they send packets on your network. Collector
credentials are never returned by any tool.

## Try it

- "Give me an overview of my lab. What can't you see?"
- "Is anything exposed on all interfaces of the Docker server?"
- "Can the Docker server resolve doubleclick.net through the Pi-hole?"
- "What changed since the last snapshot?"

## Troubleshooting

- **"No snapshots yet"**: run `labwarden collect`.
- **Server doesn't start**: run the same command in a terminal. Config errors are
  printed to stderr. stdout is reserved for the MCP protocol.
- **`from_host` probes fail**: the host must be a `linux_ssh` target, with the
  wrapper and tools from `deploy/ssh/README.md` installed.
