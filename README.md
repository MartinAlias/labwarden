# LabWarden

A **read-only** AI network & security engineer for your homelab.

LabWarden observes your network (devices, IPs/VLANs, firewall rules, containers,
DNS, logs), keeps a versioned picture of it, and helps you answer questions like
*"why can't my NAS reach the internet?"*. It observes, diagnoses, recommends a
fix you apply yourself, and then verifies it. It also documents your lab and
teaches you how to reach your goals with the hardware you already own.

> **Status:** Phase 0 (foundation) is complete. Phase 1 (MVP) is in progress, and
> all four read-only collectors (Pi-hole v6, Docker, Linux SSH, network
> discovery), the safe network probes and the **MCP server** are done, so
> Claude Desktop and Claude Code can use LabWarden today (see [docs/mcp.md](docs/mcp.md)).
> The built-in AI agent comes next. Progress is tracked in
> [docs/STATUS.md](docs/STATUS.md), with a machine-readable copy in
> [docs/status.json](docs/status.json).

## Read-only by design

LabWarden never changes your systems. This is enforced in three layers:

1. **Credentials:** every integration uses a read-only account or API key.
2. **Transport:** Docker is read through a GET-only socket proxy, and SSH uses
   a forced-command wrapper that only runs allowlisted commands.
3. **Code:** collector plugins may only define read-only methods (checked when
   the class is defined), remote commands must match an allowlist, and there is
   no "run arbitrary command" tool for the AI to call.

## Quick start

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```sh
uv sync
cp examples/labwarden.yaml labwarden.yaml
cp examples/inventory.yaml inventory.yaml   # edit to describe your lab

uv run labwarden check      # validate config
uv run labwarden collect    # take a snapshot
uv run labwarden show       # summarize it
uv run labwarden diff       # what changed since the previous snapshot
```

## Concepts

- **Lab Model:** one vendor-neutral schema for everything (devices, interfaces,
  addresses, VLANs, subnets, routes, DNS, firewall/NAT rules, containers,
  services, links, logs). Collectors translate vendor data into it, so
  diagnosis and docs work the same whether you run OPNsense, UniFi or a
  consumer router.
- **Collectors:** plugins that read one source. Each declares what parts of the
  model it `provides`, so the agent knows its blind spots. Third-party plugins
  register via the `labwarden.collectors` entry point group.
- **Snapshots:** every `collect` is saved to SQLite. Diffs between snapshots
  power change tracking, drift detection and fix verification.

## CLI reference

| Command | What it does |
|---|---|
| `labwarden plugins` | List installed collector plugins and what they provide |
| `labwarden check` | Validate config and every target's options (no connections) |
| `labwarden collect [--label X]` | Run all collectors and save a snapshot |
| `labwarden snapshots` | List snapshots, newest first |
| `labwarden show [-s ID] [--kind devices]` | Summarize a snapshot, or dump one collection as JSON |
| `labwarden diff [OLD] [NEW]` | What changed (default: the last two snapshots) |
| `labwarden mcp` | Run the MCP server over stdio for Claude Desktop / Claude Code ([docs/mcp.md](docs/mcp.md)) |
| `labwarden probe ping\|traceroute\|dns\|tcp\|http ... [--from TARGET]` | Run one safe, rate-limited probe locally, or from a `linux_ssh` host |

All commands accept `--config/-c PATH` (default `./labwarden.yaml`, or `$LABWARDEN_CONFIG`).

## Documentation

- [Design plan](docs/PLAN.md): architecture, safety model and roadmap
- [Project status](docs/STATUS.md): what's done and what's next
- [Writing a collector plugin](docs/writing-a-collector.md)

## Development

```sh
uv run pytest
uv run ruff check .
uv run ruff format --check .
```
