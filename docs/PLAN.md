# LabWarden Design Plan

## Context

> Approved design, 2026-10-05. Progress against it is tracked in [STATUS.md](STATUS.md).

LabWarden is an AI agent that acts as a homelab's network/security engineer. It should:
- **Observe** your network config, IP/VLAN inventory, firewall rules, Docker containers, logs, hardware and docs, with **read-only** access.
- **Diagnose** questions like "why can't my NAS reach the internet?" using an observe → hypothesize → test loop.
- **Recommend** changes, then **verify** them after you apply them yourself.
- **Document** the lab automatically.
- **Teach** people how to reach their goals with the hardware they already own.
- Be **portable**, so anyone can install it on their own homelab.

The project directory `D:\CodeProjects\AI_Home_NetSecEngineer` is empty, so this is greenfield. Your lab today is a Pi-hole, with a Docker server coming soon and no firewall yet. The MVP therefore targets integrations that work anywhere (Linux, Docker, Pi-hole, discovery). Firewall connectors come next, starting with the one recommended below.

**Decisions so far:**
- **Architecture:** MCP server plus our own agent.
- **LLM backend:** pluggable. Claude is the default; Ollama and other OpenAI-compatible endpoints are supported for fully local use.
- **Language:** Python. You didn't pick one, and Python has the best network/Docker libraries and the official MCP SDK.

---

## Architecture

```
          ┌───────────── Interfaces ─────────────┐
          │ CLI (ask/diagnose/docs) │ Web UI (P3)│   Any MCP client
          └────────────┬─────────────────────────┘   (Claude Desktop/Code)
                       │                                   │
                ┌──────▼──────┐   tools/resources   ┌──────▼──────┐
                │ Agent loop  │ ──────────────────▶ │ MCP server  │
                │ + playbooks │                     └──────┬──────┘
                └──────┬──────┘                            │
                LLM provider layer                 ┌───────▼────────┐
           (Anthropic | OpenAI-compat/Ollama)      │  Core services │
                + redaction filter                 │ Lab Model, probes,
                                                   │ firewall sim, docs,
                                                   │ snapshot/diff, KB │
                                                   └───────┬────────┘
                                                   ┌───────▼────────┐
                                                   │ Collector plugins (read-only)
                                                   │ linux-ssh, docker, pihole,
                                                   │ discovery, snmp, opnsense…
                                                   └────────────────┘
```

### 1. Lab Model (the core abstraction that makes it portable)
A vendor-neutral normalized schema built with Pydantic and stored in SQLite with timestamped snapshots:
`Device, Interface, Address, Vlan, Subnet, Route, DhcpScope, DnsRecord, FirewallRule, NatRule, Container, Service/Port, LogEvent, HardwareSpec, Link`.
- Every collector maps vendor data into this schema. Diagnosis, docs and advice only ever read the model, never vendor formats.
- Snapshots enable **diffs** ("what changed since yesterday?"), drift detection, and change verification.

### 2. Read-only collector plugins
Plugins are discovered via Python entry points, so the community can add vendors without touching the core.

| Phase | Plugins |
|-------|---------|
| MVP | `linux_ssh`, `docker`, `pihole`, `discovery` |
| Phase 2 | `opnsense`, `snmp`, `syslog` |
| Later | `pfsense`, `unifi`, `proxmox`, `truenas`, `synology`, `openwrt`, `mikrotik` |

MVP plugin details:
- `linux_ssh` runs an allowlisted set of commands: `ip -j addr/route/link`, `ss -tulpn`, `resolvectl`, `nft -j list ruleset`, `journalctl` tail.
- `docker` reads containers, networks, port publishes and recent logs.
- `pihole` uses the v6 API to read DNS queries, blocklists, DHCP leases and local DNS.
- `discovery` uses ARP/ping sweep, nmap service scan (opt-in) and mDNS.

Each plugin declares a `capabilities` manifest saying what model objects it provides, so the agent knows its blind spots.

### 3. Read-only enforcement, defense in depth
Read-only is enforced at three layers, so a misbehaving LLM physically cannot change anything:
1. **Credentials:** read-only accounts and API keys. The OPNsense API user gets only read privileges, and the Pi-hole token is read scope.
2. **Transport:**
   - Docker is reached only through `tecnativa/docker-socket-proxy`, with `POST=0` and the container and network endpoints only.
   - SSH uses a dedicated `labwarden` user with `command=` forced to a wrapper script that enforces the allowlist.
3. **Code:**
   - Collectors expose only `get_*`/`list_*` methods.
   - There is no generic "run shell" tool.
   - Commands are argv arrays checked against the allowlist, never shell strings.

Write mode is **not built**. A future opt-in "apply" mode is noted on the roadmap only.

### 4. Safe active probes (needed for diagnose and verify)
Probes: `ping`, `traceroute`, `dns_resolve(server=…)`, `tcp_connect`, `http_head`, `arp_lookup`.
- They run **from the agent host**, or **from a target host** via allowlisted SSH commands. "From the NAS's perspective" matters for the NAS question.
- Probes are rate-limited and non-intrusive.

### 5. Firewall/path reasoning
`firewall.simulate(src, dst, proto, port)` evaluates normalized rules plus NAT plus routes, and returns the matching rule chain. This explains *why* traffic is blocked without sending packets. It ships in Phase 2, alongside the OPNsense and nftables parsers.

### 6. MCP server (`labwarden-mcp`)
Built on the official `mcp` Python SDK, over stdio and streamable HTTP.
- **Tools:**
  - Inventory: `inventory.search`, `device.get`
  - Network: `network.subnets`, `network.vlans`, `routes.get`
  - Firewall: `firewall.rules`, `firewall.simulate`
  - DNS and Docker: `dns.records`, `docker.containers`
  - Logs and probes: `logs.search`, `probe.*`
  - Change tracking and docs: `snapshot.diff`, `docs.search`, `kb.search`
- **Resources:** generated docs pages and the current Lab Model summary.
- **Prompts:** the playbooks (e.g. `diagnose_connectivity`).

It works immediately inside Claude Desktop or Claude Code, with no custom UI needed.

### 7. Agent loop and playbooks
The agent is a provider-agnostic tool-use loop that calls the same core services as the MCP server (in-process).

**Workflow, enforced by the system prompt and output schema:**
1. **Observe:** gather facts with tools.
2. **Hypothesize:** produce a ranked list of causes.
3. **Test:** run probes or the firewall simulation to confirm or eliminate each cause.
4. **Diagnose:** state the root cause with evidence citations (which tool output proved it).
5. **Recommend:** step-by-step changes, written for *the user's specific hardware/UI*, each with a risk note and a rollback.
6. **Verify:** when the user says "done", re-run the same tests and diff against the snapshot.

**Playbooks** are YAML/Markdown decision trees the agent follows and the community can extend. Example, `no_internet`:

> link → IP/DHCP lease → default gateway reachable → DNS resolves (Pi-hole up? blocked?) → firewall/NAT egress → upstream/ISP

### 8. Documentation generator
`labwarden docs build` writes a Markdown docs site (optionally into a git repo so changes are versioned) containing:
- Network overview with a **Mermaid topology diagram**
- IP/VLAN plan table
- Device and hardware inventory
- Firewall rule summary in plain English
- Container/service catalog with exposed ports
- DNS records
- **Changelog** auto-built from snapshot diffs
- A security findings page covering:
  - exposed ports
  - containers running as root or privileged
  - default creds risk
  - flat network

### 9. Advisor / teaching mode
- **Hardware KB:** curated YAML of device capabilities, e.g. "unmanaged switch = no VLANs", "Pi 4 = 1 NIC", "router X supports VLAN tagging". The KB is extendable.
- **Goal guides:** "isolate IoT", "safely expose a service (reverse proxy / Tailscale / Cloudflare Tunnel)", "network-wide ad-blocking", "backups", "monitoring", "guest Wi-Fi".
- **`labwarden advise "<goal>"`** combines the current inventory, the KB and a guide into a tailored design. That design includes:
  - what's possible with the current gear
  - the minimum purchase if something is needed
  - step-by-step instructions
  - "why" explanations for learning
- A **lab security score** with prioritized improvements.

### 10. LLM provider layer and privacy
- Interface: `chat(messages, tools) -> response`. Adapters:
  - `anthropic`: default `claude-sonnet-5-5`, with optional `claude-opus-5-5` for deep diagnosis
  - `openai_compat`: Ollama, LM Studio, vLLM
- A **redaction filter** runs before any cloud call. It always strips secrets and tokens. Public IPs, hostnames and MACs can optionally be swapped for stable pseudonyms, then restored in the output.
- The local-model path is documented as "fully offline"; reasoning quality may be lower.

### 11. Deployment (where it runs)
- It runs as a **Docker Compose stack on your new Docker server**:
  - `labwarden` service, which hosts the MCP server, web UI and scheduler
  - `docker-socket-proxy`
  - Volume for SQLite and docs
- Config is `labwarden.yaml` (targets and plugins); secrets live in `.env`.
- `labwarden init` is a wizard that does three things:
  - discovers the subnet
  - suggests targets
  - prints the exact commands to create read-only users and keys on each device
- A scheduler collects snapshots every N minutes and rebuilds docs nightly.
- It can also run via `pipx install labwarden` on any machine, for people without Docker.

### Firewall recommendation for your lab (also the first firewall plugin)
- **Firewall:** **OPNsense** on a fanless mini PC with 2+ Intel i226 2.5G NICs, roughly $150–250.
  - It's free and open source, VLAN-capable, and has a clean REST API with fine-grained **read-only** API users. That makes it the ideal first firewall connector.
  - It works well with the Pi-hole: point OPNsense DHCP's DNS at the Pi-hole, and Unbound at the upstream.
- **Switch:** pair it with a cheap **managed (802.1Q) switch** so VLANs (trusted / IoT / servers / guest) become possible. The advisor will explain this tradeoff.
- **Alternative:** pfSense CE is also fine, but its API is less standard. Plan a Phase-4 plugin.

---

## Repo layout
```
labwarden/
  pyproject.toml            # uv-managed; entry points for plugins
  src/labwarden/
    model/                  # Pydantic Lab Model + SQLite snapshot store, diff
    collectors/             # base.py (Collector ABC, capability manifest, allowlist), linux_ssh, docker, pihole, discovery, opnsense
    probes/                 # ping, traceroute, dns, tcp, http — local + via-ssh runners
    analysis/               # firewall simulator, path reasoning, security findings
    agent/                  # loop.py, providers/{anthropic,openai_compat}.py, redaction.py, prompts/
    playbooks/              # *.yaml decision trees
    kb/                     # hardware/*.yaml, guides/*.md
    docs_gen/               # Jinja2 templates → Markdown + Mermaid
    mcp_server/             # tool/resource/prompt registration
    cli.py                  # Typer: init, collect, ask, diagnose, verify, docs, advise, mcp
    web/                    # FastAPI + HTMX (Phase 3)
  deploy/                   # docker-compose.yml, ssh-allowlist wrapper script, read-only setup guides per vendor
  testlab/                  # docker-compose fault-injection lab (see Verification)
  tests/                    # unit tests w/ recorded fixtures, scenario evals
```

## Phased roadmap
| Phase | Deliverable |
|---|---|
| **0 – Skeleton** | Repo, Lab Model, SQLite store, plugin base with read-only guard, config, CLI shell, CI (ruff/pytest) |
| **1 – MVP** | Collectors: linux_ssh, docker (via proxy), pihole, discovery. Probes. MCP server. Agent loop with Claude and Ollama. `no_internet` + `dns_failure` + `service_unreachable` playbooks. Docs generator v1. `init` wizard. Compose deploy. |
| **2 – Firewall & verify** | OPNsense plugin, nftables parser, firewall simulator, snapshot diffs, verify loop, syslog ingestion, security findings |
| **3 – Teach & UI** | Advisor mode, hardware KB, goal guides, security score, web UI (chat + inventory + docs viewer) |
| **4 – Ecosystem** | pfSense, UniFi, Proxmox, TrueNAS, Synology, OpenWrt, MikroTik, SNMP plugins; plugin authoring guide; public release |

## Verification
- **Unit tests:** each collector parses **recorded fixture outputs**, so tests run with no live devices. There are model and diff tests, and firewall-simulator truth tables.
- **Read-only guarantees, tested:**
  - The socket proxy rejects POST.
  - The SSH wrapper rejects a non-allowlisted command.
  - The tool registry contains no mutating tool (asserted in CI).
- **Fault-injection test lab** (`testlab/`): a Docker Compose world with a router container (nftables + NAT), a Pi-hole, a fake "NAS" container and a client. Scripts inject faults:
  - wrong gateway
  - DNS pointed at a dead server
  - Pi-hole blocking a domain
  - firewall egress drop
  - missing port publish

  **Scenario evals** run `labwarden diagnose "why can't the NAS reach the internet?"`. Each passes only if the agent names the injected root cause with evidence, and then `verify` passes after the fault is fixed. Evals run against both Claude and a local model to track quality.
- **Real-world check:** deploy on your Docker server against your Pi-hole, run `collect` + `docs build`, review the generated docs, and ask real questions through Claude Desktop via MCP.
