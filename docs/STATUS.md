# Project Status

Where the project stands and exactly what to do next. **Update this file at the
end of every work session.** The full design is in [PLAN.md](PLAN.md).

_Last updated: 2026-10-06_

## Current phase: Phase 0 complete → starting Phase 1

### Phase 0 – Skeleton ✅ (done 2026-10-06)

| Piece | Where | Notes |
|---|---|---|
| Lab Model (14 entity types) | `src/labwarden/model/entities.py`, `lab.py` | Pydantic, `extra="forbid"`. Each entity has `_key_fields` for identity across snapshots. |
| Snapshot store | `src/labwarden/model/store.py` | SQLite, one row per snapshot, model stored as JSON. |
| Snapshot diff | `src/labwarden/model/diff.py` | Added/removed/changed by key; field-level changes; ignores `source` and `log_events`. |
| Collector base + read-only guard | `src/labwarden/collectors/base.py` | Public methods must start with a read-only verb; `provides` manifest checked. |
| Command allowlist | `src/labwarden/collectors/allowlist.py` | argv-only, exact-length match, `re:` tokens, rejects shell metacharacters. Not used yet; for `linux_ssh` and probes. |
| Plugin registry | `src/labwarden/collectors/registry.py` | Built-ins + `labwarden.collectors` entry points. |
| Runner | `src/labwarden/collectors/runner.py` | Per-target error isolation, merges models, stamps `source`. |
| `manual` collector | `src/labwarden/collectors/manual.py` | Hand-declared inventory YAML. |
| Config | `src/labwarden/config.py` | YAML + `${VAR}`/`${VAR:-default}` + `.env`. |
| CLI | `src/labwarden/cli.py` | `version, plugins, check, collect, snapshots, show, diff`. |
| Tests | `tests/` | 37 tests, all passing. |
| CI | `.github/workflows/ci.yml` | ruff + pytest, Ubuntu/Windows × py3.11–3.13. |

### Phase 1 – MVP ⏭️ (next)

Work through these in order. Each step should land with tests using **recorded
fixture outputs** (`tests/fixtures/<plugin>/...`), so no live devices are needed.

1. **`pihole` collector** (`collectors/pihole.py`). Uses the Pi-hole **v6** REST API:
   - Auth: `POST /api/auth` with the app password gets a session `sid`. Log out with `DELETE /api/auth` at the end. This is the only non-GET call and it doesn't change config. Document it in the guard's docstring.
   - Read: `/api/config` (DNS upstreams, DHCP settings), `/api/dhcp/leases`, `/api/config/dns/hosts` (local DNS), `/api/stats/summary`.
   - Maps to: `dns_records`, `dhcp_scopes`, `devices` (from leases, kind=client), `addresses`.
   - Add `httpx` as a dependency.
2. **`docker` collector** (`collectors/docker.py`). Talks HTTP to a **docker-socket-proxy** (`tcp://host:2375`), GET only:
   - `/containers/json?all=1` and `/containers/{id}/json` (privileged, user, restart policy, ports, networks), plus `/networks`.
   - Maps to `containers`, `subnets` (docker networks), `services`.
   - Use plain `httpx`, not the docker SDK, so a mutating call can't happen by accident.
3. **`linux_ssh` collector** (`collectors/linux_ssh.py`). Uses `asyncssh` or `paramiko` with key auth:
   - Commands go through `CommandAllowlist`: `ip -j addr`, `ip -j route`, `ip -j link`, `ss -H -tulpn`, `resolvectl status`, `nft -j list ruleset` (optional; needs a sudoers entry).
   - Maps to `interfaces`, `addresses`, `routes`, `services`, `firewall_rules` (nft parse can be minimal now; full parser is Phase 2).
   - Also write `deploy/ssh/labwarden-ssh-wrapper.sh` (forced-command allowlist on the remote host) and `deploy/ssh/README.md` (how to create the `labwarden` user plus `authorized_keys` with `command=`).
4. **`discovery` collector**: ARP table + ping sweep of configured subnets. nmap service scan is opt-in.
5. **Probes** (`src/labwarden/probes/`): `ping`, `traceroute`, `dns_resolve(server=)`, `tcp_connect`, `http_head`. Each runs locally, or remotely via `linux_ssh` + allowlist. Rate-limited.
6. **MCP server** (`src/labwarden/mcp_server/`). Uses the official `mcp` SDK (FastMCP) over stdio:
   - Tools read the latest snapshot: inventory search, device get, subnets, routes, DNS, containers, firewall rules, snapshot diff.
   - Plus probe tools.
   - Add `labwarden mcp` CLI command and a Claude Desktop config snippet in the docs.
   - CI test: assert no tool name starts with a mutating verb.
7. **Agent loop** (`src/labwarden/agent/`):
   - Provider interface with `anthropic` (default `claude-sonnet-5-5`) and `openai_compat` (Ollama) adapters.
   - The same tools as the MCP server, called in-process.
   - `redaction.py` scrubs secrets before cloud calls.
   - CLI: `labwarden ask "..."` and `labwarden diagnose "..."`.
8. **Playbooks** (`src/labwarden/playbooks/*.yaml`): `no_internet`, `dns_failure`, `service_unreachable`.
9. **Docs generator v1** (`labwarden docs build`): Markdown with a Mermaid topology, IP plan, inventory, containers and exposed ports, plus a changelog from diffs.
10. **`init` wizard + `deploy/docker-compose.yml`** (labwarden + docker-socket-proxy).

### Phase 2+

See the roadmap table in [PLAN.md](PLAN.md#phased-roadmap).

## The user's lab (the real-world test bed)

- **ISP router:** combo modem/router at 192.168.1.1. It's the gateway, DHCP server and Wi-Fi.
- **Pi-hole:** Raspberry Pi 4 (4 GB) at 192.168.1.2. It's the DNS server.
- **Docker server:** new box at 192.168.1.10, not set up yet. LabWarden will be deployed here.
- **Switch:** unmanaged, so no VLANs yet.
- **Firewall:** none yet. The recommendation is OPNsense on a mini PC with 2+ Intel i226 NICs, plus a managed 802.1Q switch. The OPNsense collector is the first Phase 2 plugin.

These IPs are placeholders from `examples/inventory.yaml`. Confirm the real ones with the user.

## Dev environment notes (Windows machine)

- Python 3.12.10, uv, git, gh and Docker Desktop are installed. GitHub CLI is logged in as `MartinAlias`.
- **PATH quirk:** Claude Code sessions may not see `python`/`uv` on PATH until the parent terminal/IDE is restarted. Fallback absolute paths:
  - uv: `C:/Users/Marti/AppData/Local/Microsoft/WinGet/Packages/astral-sh.uv_Microsoft.Winget.Source_8wekyb3d8bbwe/uv.exe`
  - python: `C:/Users/Marti/AppData/Local/Programs/Python/Python312/python.exe`
  - gh: `C:/Program Files/GitHub CLI/gh.exe`
- Docker Desktop needs a first launch (WSL 2 setup) before `testlab/` work.
