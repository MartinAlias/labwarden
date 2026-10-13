"""Shared helpers for collectors that read HTTP APIs."""

from __future__ import annotations

from collections.abc import Callable, Iterable

import httpx

from labwarden.collectors.base import ReadOnlyViolation


def read_only_guard(
    plugin: str, allowed_non_get: Iterable[tuple[str, str]] = ()
) -> Callable[[httpx.Request], None]:
    """Build an httpx request hook that refuses everything except GET.

    ``allowed_non_get`` lists exact ``(method, path)`` pairs that are allowed
    anyway, such as a session login that doesn't change configuration. Each
    exception has to be justified in the collector's docstring.
    """
    allowed = frozenset(allowed_non_get)

    def guard(request: httpx.Request) -> None:
        if request.method == "GET" or (request.method, request.url.path) in allowed:
            return
        raise ReadOnlyViolation(f"{plugin} collector refused {request.method} {request.url.path}")

    return guard
