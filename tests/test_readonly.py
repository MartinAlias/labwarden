"""The read-only guarantees are the product's core promise, so they get explicit tests."""

from __future__ import annotations

import pytest

from labwarden.collectors import Collector, CommandAllowlist, ReadOnlyViolation
from labwarden.collectors.registry import available_collectors
from labwarden.model.lab import LabModel


def test_collector_with_mutating_method_is_rejected_at_definition() -> None:
    with pytest.raises(ReadOnlyViolation, match="restart_container"):

        class Bad(Collector):
            plugin = "bad"

            def collect(self) -> LabModel:
                return LabModel()

            def restart_container(self) -> None: ...


@pytest.mark.parametrize("decorator", [staticmethod, classmethod])
def test_mutating_static_and_class_methods_are_rejected(decorator) -> None:
    with pytest.raises(ReadOnlyViolation):
        type("Bad", (Collector,), {"plugin": "bad", "set_rule": decorator(lambda *a: None)})


def test_read_only_and_private_methods_are_allowed() -> None:
    class Good(Collector):
        plugin = "good"
        provides = frozenset({"devices"})

        def collect(self) -> LabModel:
            return LabModel()

        def get_status(self) -> None: ...

        def list_things(self) -> None: ...

        def _helper(self) -> None: ...

    assert Good.plugin == "good"


def test_unknown_provides_is_rejected() -> None:
    with pytest.raises(TypeError, match="unknown collections"):
        type("Bad", (Collector,), {"plugin": "bad", "provides": frozenset({"bogus"})})


def test_all_installed_plugins_pass_the_guard() -> None:
    # Importing a plugin runs the guard; make sure every registered one loaded.
    assert {"discovery", "docker", "linux_ssh", "manual", "pihole"} <= set(available_collectors())


class TestAllowlist:
    allowlist = CommandAllowlist(
        [
            ("ip", "-j", "addr"),
            ("ping", "-c", r"re:[1-5]", r"re:[A-Za-z0-9.:-]+"),
        ]
    )

    def test_exact_match(self) -> None:
        self.allowlist.check(["ip", "-j", "addr"])

    def test_regex_tokens(self) -> None:
        self.allowlist.check(["ping", "-c", "3", "192.168.1.1"])
        assert not self.allowlist.is_allowed(["ping", "-c", "100", "192.168.1.1"])

    @pytest.mark.parametrize(
        "argv",
        [
            [],
            ["ip", "-j", "addr", "add", "10.0.0.1/24", "dev", "eth0"],  # extra args
            ["ip", "addr"],  # too few
            ["rm", "-rf", "/"],
            ["ping", "-c", "1", "x;reboot"],  # shell metacharacters
            ["ping", "-c", "1", "$(reboot)"],
            ["ping", "-c", "1", "a\nreboot"],
        ],
    )
    def test_rejected(self, argv: list[str]) -> None:
        with pytest.raises(ReadOnlyViolation):
            self.allowlist.check(argv)

    def test_program_must_be_literal(self) -> None:
        with pytest.raises(ValueError):
            CommandAllowlist([("re:.*",)])
