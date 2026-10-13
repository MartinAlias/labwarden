# Writing a Collector Plugin

A collector reads one source (a router API, a host over SSH, a NAS...) and
translates what it sees into a `LabModel`. It must **never change** the system
it reads.

## Minimal example

```python
from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from labwarden.collectors.base import Collector
from labwarden.model.entities import Device
from labwarden.model.lab import LabModel


class AcmeOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str
    api_key: str


class AcmeCollector(Collector):
    plugin = "acme"  # used as `plugin: acme` in config
    description = "Acme routers via the read-only REST API."
    provides = frozenset({"devices", "routes"})  # what this collector may return
    Options = AcmeOptions  # validates the `options:` block

    def collect(self) -> LabModel:
        data = self._fetch_status()
        return LabModel(devices=[Device(name=data["hostname"], kind="router")])

    def _fetch_status(self) -> dict:  # private helpers start with "_"
        ...
```

## Rules the framework enforces

- **Read-only method names.** Public methods must start with `get_`, `list_`, `read_`, `fetch_`, `parse_`, `collect` or `describe`. A collector defining `reboot()` or `set_rule()` raises `ReadOnlyViolation` as soon as the class is defined.
- **Declared coverage.** Return only collections listed in `provides`. Anything else makes the target fail, so the agent can trust which data each source covers.
- **Remote commands.** If you run commands on a host, build argv lists and check them with a `CommandAllowlist` before running. Never use a shell.
- **Credentials.** Document how to create a *read-only* account for your source.

## Reusing the built-in safety helpers

- **HTTP APIs.** Pass `read_only_guard(plugin, allowed_non_get=...)` from
  `labwarden.collectors.http` as an httpx request hook. Every non-GET request
  is then refused before it leaves the process. List any exception, such as a
  session login, as an exact `(method, path)` pair and justify it in the
  module docstring. Expose a `_transport` class attribute, so tests can swap
  in `httpx.MockTransport`. Examples: `pihole.py`, `docker.py`.
- **Commands over SSH.** Put every command in a module-level constant and
  build a `CommandAllowlist` from it. Check each argv right before it's sent.
  Mirror the list in the remote forced-command wrapper, and add a test that
  keeps the two identical. Expose a `_runner` attribute, so tests can answer
  commands from fixtures. Example: `linux_ssh.py` with `deploy/ssh/`.
- **Pure parsers.** Keep the API/command-output → `LabModel` translation in
  pure functions (`parse_pihole`, `parse_docker`, `parse_linux`), so most
  tests need no fakes at all.

## Config

```yaml
targets:
  - name: main-router
    plugin: acme
    options:
      url: https://192.168.1.1
      api_key: ${ACME_API_KEY}     # from the environment or .env
```

Relative paths in options should be resolved against `self.base_dir` (the
config file's directory).

## Registering

- **Built-in:** add the class to `_BUILTINS` in `src/labwarden/collectors/registry.py` and to `[project.entry-points."labwarden.collectors"]` in `pyproject.toml`.
- **Third-party package:** declare the entry point in your own `pyproject.toml`:

  ```toml
  [project.entry-points."labwarden.collectors"]
  acme = "labwarden_acme.collector:AcmeCollector"
  ```

Check it shows up with `labwarden plugins`.

## Testing

Record real responses once (scrub secrets, MACs and public IPs) into
`tests/fixtures/<plugin>/`. Then test that parsing them produces the expected
`LabModel`. Tests must not touch the network.
