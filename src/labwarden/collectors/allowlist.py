"""Allowlist for commands that collectors and probes run on remote hosts.

Commands are always argv lists, never shell strings, and each one must match an
allowlisted pattern exactly. A pattern is a tuple of tokens; each token is
either a literal or a regular expression written as ``re:<pattern>`` that must
match the whole argument.

The same allowlist is rendered into the SSH forced-command wrapper (``deploy/``),
so it is enforced on the remote host too, not just in our process.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from labwarden.collectors.base import ReadOnlyViolation

# Characters that only make sense to a shell. Arguments are never interpreted by
# a shell, but rejecting them anyway is cheap defense in depth.
_SHELL_META = re.compile(r"[;&|`$<>\\\n\r]")

Pattern = tuple[str, ...]


class CommandAllowlist:
    def __init__(self, patterns: Iterable[Sequence[str]]) -> None:
        self._patterns: list[tuple[Pattern, list[re.Pattern[str] | str]]] = []
        for pattern in patterns:
            pattern = tuple(pattern)
            if not pattern:
                raise ValueError("empty allowlist pattern")
            if pattern[0].startswith("re:"):
                raise ValueError(f"the program name must be a literal: {pattern}")
            matchers: list[re.Pattern[str] | str] = [
                re.compile(tok[3:]) if tok.startswith("re:") else tok for tok in pattern
            ]
            self._patterns.append((pattern, matchers))

    @property
    def patterns(self) -> list[Pattern]:
        return [p for p, _ in self._patterns]

    def is_allowed(self, argv: Sequence[str]) -> bool:
        if not argv or any(_SHELL_META.search(arg) for arg in argv):
            return False
        return any(self._matches(matchers, argv) for _, matchers in self._patterns)

    def check(self, argv: Sequence[str]) -> None:
        if not self.is_allowed(argv):
            raise ReadOnlyViolation(f"command not in read-only allowlist: {list(argv)!r}")

    @staticmethod
    def _matches(matchers: list[re.Pattern[str] | str], argv: Sequence[str]) -> bool:
        if len(matchers) != len(argv):
            return False
        for matcher, arg in zip(matchers, argv, strict=True):
            if isinstance(matcher, str):
                if matcher != arg:
                    return False
            elif not matcher.fullmatch(arg):
                return False
        return True
