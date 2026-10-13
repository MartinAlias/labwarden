# Project Status

Where the project stands and exactly what to do next. **Update this file at the
end of every work session.** The full design is in [PLAN.md](PLAN.md).

_Last updated: 2026-10-13_

## Current phase: Phase 1 in progress (steps 1–3 of 11 done)

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
| Tests | `tests/` | 37 tests at end of Phase 0 (98 after the Pi-hole, Docker and Linux SSH collectors). |
| CI | `.github/workflows/ci.yml` | ruff + pytest, Ubuntu/Windows × py3.11–3.13. |

### Phase 1 – MVP 🚧 (in progress)

Work through these in order. Each step should land with tests using **recorded
fixture outputs** (`tests/fixtures/<plugin>/...`), so no live devices are needed.

1. ✅ **`pihole` collector** (`collectors/pihole.py`, done 2026-10-13):
   - Reads `/api/config`, `/api/dhcp/leases` and `/api/info/version`. All three are GET; `/api/config` already includes `dns.hosts`, so `/api/config/dns/hosts` isn't called separately.
   - Login and logout use `POST`/`DELETE /api/auth` with the `X-FTL-SID` header. An httpx request hook (`_guard_request`) refuses every other non-GET call.
   - Maps to `devices` (the Pi-hole plus one `client` per lease), `addresses`, `dns_records` (A/AAAA/CNAME), and `dhcp_scopes` + `subnets` when Pi-hole DHCP is active.
   - Upstream DNS servers and the local domain are stored as Pi-hole device tags (`dns-upstream:…`, `dns-domain:…`), because no entity fits yet. Revisit when the `dns_failure` playbook needs them.
   - Query stats aren't stored, because they would add diff noise.
   - If `dhcp.netmask` is unset, the scope's subnet is guessed (/24 if the range fits).
   - It logs a warning if `webserver.api.app_sudo` is on.
   - DHCP static reservations (`dhcp.hosts`) aren't parsed yet.
   - 21 tests in `tests/test_pihole.py`. ⚠️ Fixtures were written from the FTL OpenAPI spec, **not recorded from a real Pi-hole**.
   - ⏸️ **Live Pi-hole setup is deferred to the very end of Phase 1, at the user's request (2026-10-13).** Nothing has been set up against the real Pi-hole: no app password, no `.env` entry, no `labwarden.yaml` target, no recorded fixtures. Don't suggest doing it before the other Phase 1 steps are finished. See the final step below.
2. ✅ **`docker` collector** (`collectors/docker.py`, done 2026-10-13):
   - Plain `httpx` to docker-socket-proxy. `tcp://` URLs become `http://`; `unix://` is rejected on purpose. Every non-GET call is refused by the shared `read_only_guard`, which now lives in `collectors/http.py` and is used by both collectors.
   - Reads `/containers/json?all=1`, then `/containers/{id}/json` for each container. Also reads `/networks` and `/version`; both are optional and skipped with a warning when the proxy returns 403. A blocked `/containers` is an error that names `CONTAINERS=1`.
   - Maps to `containers`, `services`, `subnets` and `devices`:
     - `containers`: image, state, networks, ports, privileged, user, restart policy.
     - `services`: published host ports of running containers, with `process=docker:<name>`.
     - `subnets`: one per Docker network, named `docker:<host>/<network>`.
     - `devices`: the host, with the engine version as `os`.
   - Stopped containers report their *configured* port bindings, so stopping one doesn't show as "port removed" in diffs.
   - `Config.Env` and `Config.Labels` (where secrets live) are never copied into the model. A test proves this.
   - Known gap: every Docker host has `172.17.0.0/16`, and Subnet's key is the CIDR, so with two Docker hosts the second host's default bridge is dropped on merge. Revisit if multi-host matters.
   - 18 tests in `tests/test_docker.py`. Fixtures were written from the Engine API reference, not recorded from a live host; the Docker server isn't set up yet.
3. ✅ **`linux_ssh` collector** (`collectors/linux_ssh.py`, done 2026-10-13):
   - Uses paramiko with key auth. `RejectPolicy` means unknown host keys are refused, never auto-trusted. Agent and default keys are disabled; only `key_file` is used.
   - Every command is a constant in `COMMANDS`. `CommandAllowlist` checks it in the collector *and* in `_SshSession.run`, right before it's sent. Output is capped at 8 MB per command.
   - Commands:
     - `ip -d -j addr`
     - `ip -j route` and `ip -j -6 route`
     - `ss -H -tulpn`
     - `cat /etc/os-release`
     - `cat /etc/resolv.conf` and `resolvectl dns`
     - opt-in `sudo -n nft -j list ruleset` (`nftables: true`)
     - `ip -j link` was dropped, because `ip -d -j addr` already has the link data plus VLAN IDs. `cat /etc/resolv.conf` and `resolvectl dns` replace `resolvectl status`, which is unstable text.
   - Maps to `devices` (os from os-release, `dns-server:` tags), `interfaces` (VLAN ID from `linkinfo`), `addresses`, `routes`, `services` and `firewall_rules`.
     - `lo` and `veth*` are skipped to avoid diff noise.
     - IPv6 link-local addresses and non-unicast routes are skipped.
     - A `*` listen address becomes `::`.
   - nftables parsing is minimal, as planned:
     - It covers filter chains, the src/dst address and port matches, and each base chain's default policy, emitted as the last rule.
     - Unknown matches go into `description`, so they never silently become "any".
     - Jumps, NAT and log-only rules are skipped. The full parser is Phase 2.
   - `deploy/ssh/labwarden-ssh-wrapper.sh` is the forced command. It runs only exact matches of the same command lines and exits 126 otherwise. `deploy/ssh/README.md` covers the user, `authorized_keys` with `restrict,command=`, host-key trust, the optional sudoers line and removal.
   - 20 tests in `tests/test_linux_ssh.py`, covering:
     - parsing every command
     - nft rules
     - fallbacks
     - session safety (RejectPolicy, no agent, off-list commands never sent)
     - the wrapper's case list matching `COMMANDS`
     - the wrapper refusing injection attempts (it runs the real script under `sh`)
   - Fixtures were written to match the output formats, not recorded from a live host.
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
11. **Live Pi-hole hookup (last, by user request):** do these steps in order.
    - Create an app password and confirm `webserver.api.app_sudo` is off.
    - Put `PIHOLE_PASSWORD` in `.env`.
    - Add the `pihole` target to `labwarden.yaml`.
    - Run `labwarden collect`.
    - Record scrubbed responses into `tests/fixtures/pihole/` to replace the spec-based ones.

### Phase 2+

See the roadmap table in [PLAN.md](PLAN.md#phased-roadmap).

## The user's lab (the real-world test bed)

What the user has (confirmed 2026-10-13):
- **ONT** (fiber) and an **ISP router**. The router is the gateway, DHCP server and Wi-Fi today, and the user believes it supports bridge mode.
- **Pi-hole** on a Raspberry Pi 4 (4 GB). It is set up and running; its LabWarden hookup is deferred, see Phase 1 step 11.
- **Server**, not set up yet. It will hold VMs: Linux and Windows machines for **hacking practice**, which must never be exposed to the public. It will run **Proxmox** (user confirmed), with LabWarden in a Docker VM.
- **Switch**: TP-Link TL-SG108S-M2, 8× 2.5G, **unmanaged** (no web UI, no 802.1Q). The plan buys a managed 2.5G core switch and reuses this one as extra wired ports on Trusted (VLAN 10).
- **Endpoints**: PCs, phones, etc. The **admin PC is `vexd-pc`**, currently at 192.168.4.67.
- **Firewall**: none yet. Recommended: OPNsense on a mini PC with 2+ Intel i226 NICs. The OPNsense collector is the first Phase 2 plugin.

The current LAN is **192.168.4.x** (inferred from vexd-pc's IP; the router's address and the prefix are unconfirmed). The 192.168.1.x IPs in `examples/inventory.yaml` are placeholders and are wrong for this lab.

**Target design (draft v4, 2026-10-13):** https://claude.ai/artifact/4RDKRyGJjjQvpnq9azoqfu
- Path: ONT → ISP router (bridge) → OPNsense → 802.1Q switch. The switch feeds a VLAN-capable AP and the Proxmox server (one trunk carrying 20/50/99).
- VLANs on `192.168.<vlan>.0/24`:
  - 10 Trusted: vexd-pc reserved at .10.67
  - 20 Servers: Pi-hole .20.2, Docker VM .20.10
  - 30 IoT
  - 40 Guest
  - 50 **Hacking lab**: isolated, no internet by default, nothing can start connections out, DNS from Unbound at .50.1
  - 99 **Management**: all admin UIs, reachable only from vexd-pc. This is the user's "centralized" answer.
- User decisions:
  - bridge mode: yes
  - management: centralized, as VLAN 99
  - Trusted → IoT: allowed
  - **vexd-pc is the only device allowed to make changes**: admin UIs and SSH of OPNsense, switch, AP, Proxmox and Pi-hole, plus access into the hacking lab. Everything else gets DNS and services only.
  - hypervisor: Proxmox
  - port forwards: none ever; remote access later via WireGuard/Tailscale on OPNsense
- Still open: server specs (CPU/RAM/disk).
- Once confirmed, the plan could become a `manual` inventory file, so LabWarden can compare the real lab against it.

## Dev environment notes (Windows machine)

- Python 3.12.10, uv, git, gh and Docker Desktop are installed. GitHub CLI is logged in as `MartinAlias`.
- **PATH quirk:** Claude Code sessions may not see `python`/`uv` on PATH until the parent terminal/IDE is restarted. Fallback absolute paths:
  - uv: `C:/Users/Marti/AppData/Local/Microsoft/WinGet/Packages/astral-sh.uv_Microsoft.Winget.Source_8wekyb3d8bbwe/uv.exe`
  - python: `C:/Users/Marti/AppData/Local/Programs/Python/Python312/python.exe`
  - gh: `C:/Program Files/GitHub CLI/gh.exe`
- Docker Desktop needs a first launch (WSL 2 setup) before `testlab/` work.
