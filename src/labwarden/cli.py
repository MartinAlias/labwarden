"""``labwarden`` command-line interface."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from labwarden import __version__
from labwarden.collectors.registry import available_collectors
from labwarden.collectors.runner import build_collector, run_collectors
from labwarden.config import Config, ConfigError, find_config, load_config
from labwarden.model.diff import LabDiff, diff_models
from labwarden.model.store import Snapshot, SnapshotStore
from labwarden.probes import (
    ProbeResult,
    dns_resolve,
    http_head,
    ping,
    remote_executor,
    tcp_connect,
    traceroute,
)

app = typer.Typer(
    help="LabWarden: a read-only AI network & security engineer for your homelab.",
    no_args_is_help=True,
    add_completion=False,
)
probe_app = typer.Typer(
    help="Run one safe, read-only network probe, locally or --from a linux_ssh target.",
    no_args_is_help=True,
)
app.add_typer(probe_app, name="probe")
console = Console()
err = Console(stderr=True)

ConfigOpt = Annotated[
    Path | None,
    typer.Option("--config", "-c", help="Path to labwarden.yaml (default: ./labwarden.yaml)."),
]


def _load(config_path: Path | None) -> Config:
    try:
        return load_config(find_config(config_path))
    except ConfigError as exc:
        err.print(f"[red]Config error:[/red] {escape(str(exc))}")
        raise typer.Exit(2) from exc


def _store(config: Config) -> SnapshotStore:
    return SnapshotStore(config.snapshot_db)


@app.command()
def version() -> None:
    """Print the LabWarden version."""
    console.print(f"labwarden {__version__}")


@app.command()
def plugins() -> None:
    """List installed collector plugins and what each one provides."""
    table = Table("Plugin", "Description", "Provides")
    for name, cls in sorted(available_collectors().items()):
        _add_row(table, name, cls.description, ", ".join(sorted(cls.provides)))
    console.print(table)


@app.command()
def check(config_path: ConfigOpt = None) -> None:
    """Validate the config file and every target's plugin options (no connections made)."""
    config = _load(config_path)
    failed = False
    for target in config.targets:
        try:
            build_collector(target, config)
        except Exception as exc:
            failed = True
            console.print(f"[red]x[/red] {escape(f'{target.name} ({target.plugin}): {exc}')}")
        else:
            state = "" if target.enabled else " [dim](disabled)[/dim]"
            console.print(f"[green]ok[/green] {escape(f'{target.name} ({target.plugin})')}{state}")
    if not config.targets:
        console.print("[yellow]No targets configured.[/yellow]")
    if failed:
        raise typer.Exit(1)


@app.command()
def collect(
    config_path: ConfigOpt = None,
    label: Annotated[str | None, typer.Option(help="Optional label for this snapshot.")] = None,
) -> None:
    """Run all enabled collectors and save the result as a new snapshot."""
    config = _load(config_path)
    result = run_collectors(config)
    snapshot_id = _store(config).save(result.model, label=label, errors=result.errors)

    console.print(f"Saved snapshot [bold]#{snapshot_id}[/bold]")
    _print_counts(result.model.counts())
    for target, message in result.errors.items():
        err.print(f"[red]Target {escape(repr(target))} failed:[/red] {escape(message)}")
    if result.errors:
        raise typer.Exit(1)


@app.command()
def mcp(config_path: ConfigOpt = None) -> None:
    """Run the MCP server over stdio (for Claude Desktop, Claude Code, ...).

    stdout carries the MCP protocol, so this command prints nothing else there.
    """
    from labwarden.mcp_server import build_server

    build_server(_load(config_path)).run("stdio")


@app.command()
def snapshots(
    config_path: ConfigOpt = None,
    limit: Annotated[int, typer.Option(help="How many to show.")] = 20,
) -> None:
    """List saved snapshots, newest first."""
    store = _store(_load(config_path))
    table = Table("ID", "Taken at (UTC)", "Label", "Failed targets")
    for info in store.history(limit):
        _add_row(
            table,
            str(info.id),
            info.taken_at.strftime("%Y-%m-%d %H:%M:%S"),
            info.label or "",
            ", ".join(info.errors) or "",
        )
    console.print(table)


@app.command()
def show(
    config_path: ConfigOpt = None,
    snapshot_id: Annotated[
        int | None, typer.Option("--snapshot", "-s", help="Snapshot ID (default: latest).")
    ] = None,
    kind: Annotated[
        str | None, typer.Option(help="Dump one collection as JSON, e.g. 'devices'.")
    ] = None,
) -> None:
    """Summarize a snapshot, or dump one collection of it as JSON."""
    snap = _get_snapshot(_store(_load(config_path)), snapshot_id)
    if kind:
        if kind not in snap.model.kinds():
            choices = escape(", ".join(snap.model.kinds()))
            err.print(f"[red]Unknown collection {escape(repr(kind))}.[/red] Choose from: {choices}")
            raise typer.Exit(2)
        data = [e.model_dump(mode="json", exclude_none=True) for e in getattr(snap.model, kind)]
        console.print_json(json.dumps(data))
        return

    console.print(f"Snapshot [bold]#{snap.id}[/bold] taken {snap.taken_at:%Y-%m-%d %H:%M:%S} UTC")
    _print_counts(snap.model.counts())
    if snap.model.devices:
        table = Table("Device", "Kind", "Management IP", "Roles", "Source")
        for d in snap.model.devices:
            _add_row(
                table,
                d.name,
                d.kind,
                str(d.management_ip or ""),
                ", ".join(d.roles),
                d.source or "",
            )
        console.print(table)


@app.command()
def diff(
    before: Annotated[int | None, typer.Argument(help="Older snapshot ID.")] = None,
    after: Annotated[int | None, typer.Argument(help="Newer snapshot ID.")] = None,
    config_path: ConfigOpt = None,
) -> None:
    """Show what changed between two snapshots.

    No IDs: the last two. One ID: that snapshot vs. the latest.
    """
    store = _store(_load(config_path))
    if before is not None:
        old = _get_snapshot(store, before)
        new = _get_snapshot(store, after)
    else:
        new = _get_snapshot(store, None)
        old = store.latest(offset=1)
        if old is None:
            err.print("[yellow]Need two snapshots to diff. Run `labwarden collect` again.[/yellow]")
            raise typer.Exit(1)
    console.print(f"Changes from #{old.id} to #{new.id}:")
    _print_diff(diff_models(old.model, new.model))


FromOpt = Annotated[
    str | None,
    typer.Option("--from", help="Run from this linux_ssh target instead of locally."),
]
JsonOpt = Annotated[bool, typer.Option("--json", help="Print the full result as JSON.")]


@probe_app.command("ping")
def probe_ping(
    host: str,
    count: Annotated[int, typer.Option(help="Echo requests to send (1-5).")] = 3,
    from_target: FromOpt = None,
    config_path: ConfigOpt = None,
    as_json: JsonOpt = False,
) -> None:
    """Ping a host."""
    _run_probe(ping, from_target, config_path, as_json, host, count=count)


@probe_app.command("traceroute")
def probe_traceroute(
    host: str,
    max_hops: Annotated[int, typer.Option(help="Maximum hops (1-30).")] = 20,
    from_target: FromOpt = None,
    config_path: ConfigOpt = None,
    as_json: JsonOpt = False,
) -> None:
    """Show the routers on the path to a host."""
    _run_probe(traceroute, from_target, config_path, as_json, host, max_hops=max_hops)


@probe_app.command("dns")
def probe_dns(
    name: str,
    record_type: Annotated[
        str, typer.Option("--type", help="Record type, e.g. A, AAAA, MX.")
    ] = "A",
    server: Annotated[
        str | None, typer.Option(help="Ask this DNS server (IP) instead of the default.")
    ] = None,
    from_target: FromOpt = None,
    config_path: ConfigOpt = None,
    as_json: JsonOpt = False,
) -> None:
    """Resolve a DNS name, optionally against one specific server."""
    _run_probe(
        dns_resolve, from_target, config_path, as_json, name, record_type=record_type, server=server
    )


@probe_app.command("tcp")
def probe_tcp(
    host: str,
    port: int,
    from_target: FromOpt = None,
    config_path: ConfigOpt = None,
    as_json: JsonOpt = False,
) -> None:
    """Check whether a TCP port accepts connections (no data is sent)."""
    _run_probe(tcp_connect, from_target, config_path, as_json, host, port)


@probe_app.command("http")
def probe_http(
    url: str,
    insecure: Annotated[
        bool, typer.Option(help="Don't verify TLS certificates (local probes only).")
    ] = False,
    from_target: FromOpt = None,
    config_path: ConfigOpt = None,
    as_json: JsonOpt = False,
) -> None:
    """Send one HTTP HEAD request and report the status (redirects are not followed)."""
    kwargs = {"verify_tls": False} if insecure else {}
    _run_probe(http_head, from_target, config_path, as_json, url, **kwargs)


def _run_probe(
    fn: Callable[..., ProbeResult],
    from_target: str | None,
    config_path: Path | None,
    as_json: bool,
    *args: object,
    **kwargs: object,
) -> None:
    try:
        if from_target:
            config = _load(config_path)
            try:
                executor = remote_executor(config, from_target)
            except (LookupError, ValueError) as exc:
                err.print(
                    f"[red]Can't run from {escape(repr(from_target))}:[/red] {escape(str(exc))}"
                )
                raise typer.Exit(2) from exc
            with executor as ex:
                result = fn(*args, executor=ex, **kwargs)
        else:
            result = fn(*args, **kwargs)
    except ValueError as exc:
        err.print(f"[red]Invalid input:[/red] {escape(str(exc))}")
        raise typer.Exit(2) from exc
    except OSError as exc:  # SSH connection problems
        err.print(f"[red]Connection failed:[/red] {escape(str(exc))}")
        raise typer.Exit(1) from exc

    if as_json:
        console.print_json(result.model_dump_json())
    else:
        mark = "[green]ok[/green]" if result.ok else "[red]fail[/red]"
        where = escape(f"from {result.source}, {result.duration_ms:g} ms")
        console.print(f"{mark} {escape(result.summary)} [dim]({where})[/dim]", highlight=False)
    raise typer.Exit(0 if result.ok else 1)


def _get_snapshot(store: SnapshotStore, snapshot_id: int | None) -> Snapshot:
    snap = store.latest() if snapshot_id is None else store.get(snapshot_id)
    if snap is None:
        what = "No snapshots yet" if snapshot_id is None else f"Snapshot #{snapshot_id} not found"
        err.print(f"[yellow]{what}.[/yellow] Run `labwarden collect` first.")
        raise typer.Exit(1)
    return snap


def _add_row(table: Table, *cells: str) -> None:
    """Add a row of plain text; device names etc. must not be parsed as Rich markup."""
    table.add_row(*(escape(c) for c in cells))


def _print_counts(counts: dict[str, int]) -> None:
    non_empty = {k: v for k, v in counts.items() if v}
    if not non_empty:
        console.print("[yellow]Nothing collected.[/yellow]")
        return
    console.print("  " + ", ".join(f"{k}: {v}" for k, v in non_empty.items()))


def _print_diff(result: LabDiff) -> None:
    if result.is_empty:
        console.print("[green]No changes.[/green]")
        return
    styles = {"added": ("+", "green"), "removed": ("-", "red"), "changed": ("~", "yellow")}
    for change in result.changes:
        mark, color = styles[change.status]
        console.print(f"[{color}]{mark} {escape(change.label())}[/{color}]", highlight=False)
        for fc in change.changes:
            console.print(
                f"    {fc.field}: {escape(repr(fc.before))} -> {escape(repr(fc.after))}",
                highlight=False,
            )


if __name__ == "__main__":
    app()
