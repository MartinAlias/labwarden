# CLAUDE.md

Guidance for AI coding sessions working on this repo.

## Start here

1. Read [docs/STATUS.md](docs/STATUS.md). It says what's done and gives the ordered next steps.
2. The full design is in [docs/PLAN.md](docs/PLAN.md). Follow it unless the user says otherwise.
3. At the end of a session, update `docs/STATUS.md` (done items, next steps, date).
   Also update `docs/status.json`: the step and phase states, `updated` and `summary`.
   The portfolio site reads it publicly, so keep IPs, hostnames and lab details out of it.

## What this is

LabWarden is a **read-only** AI network/security engineer for homelabs.
- Collector plugins read devices into a vendor-neutral **Lab Model**.
- Snapshots are stored in SQLite and diffed.
- An MCP server and an agent loop (Phase 1) diagnose problems, recommend fixes and verify them.
- It also generates docs and teaches.

## Commands

```sh
uv sync                      # install (creates .venv)
uv run pytest                # tests
uv run ruff check .          # lint
uv run ruff format .         # format (CI runs --check)
uv run labwarden --help      # CLI
```

If `uv` isn't on PATH in this environment, see the absolute paths in `docs/STATUS.md`.

## Non-negotiable rules

- **Never add a code path that modifies a target system.** Collectors may only define public methods starting with `get_ list_ read_ fetch_ parse_ collect describe` (enforced in `collectors/base.py`). Private helpers use a `_` prefix.
- Remote commands are argv lists checked by `CommandAllowlist`. Never use shell strings, and never add a generic "run command" tool.
- Docker access goes through docker-socket-proxy with GET only. Use plain HTTP, not the docker SDK.
- Every collector declares `provides`. The runner rejects anything undeclared.
- Secrets come from `${VAR}` in config or `.env`. They never go in YAML, logs, snapshots, or LLM prompts.

## Conventions

- Python ≥ 3.11, `from __future__ import annotations`, Pydantic v2 models with `extra="forbid"`.
- Line length 100; ruff rules `E F I B UP SIM RUF`.
- New collectors go in `src/labwarden/collectors/<name>.py`:
  - register them in `_BUILTINS` (`registry.py`) **and** in `pyproject.toml` entry points
  - put tests with recorded fixtures in `tests/fixtures/<name>/`
  - see [docs/writing-a-collector.md](docs/writing-a-collector.md)
- CLI output: anything user- or device-supplied passes through `rich.markup.escape` (or `_add_row`), because device names can contain `[...]`.
- YAML gotcha: unquoted `off`/`no`/`yes` parse as booleans.
- Keep tests offline. No live network access in the test suite.
