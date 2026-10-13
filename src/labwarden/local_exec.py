"""Run an allowlisted command on the machine LabWarden itself runs on."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence

from labwarden.collectors.allowlist import CommandAllowlist

#: (exit status, stdout, stderr)
CommandResult = tuple[int, str, str]


def run_local(
    argv: Sequence[str], allowlist: CommandAllowlist, timeout: float = 600
) -> CommandResult:
    """Run ``argv`` without a shell, after checking it against ``allowlist``.

    A missing program returns 127 and a timeout returns 124, like a shell
    would, so callers can treat "not installed" as data rather than a crash.
    """
    allowlist.check(argv)  # the last check before anything runs
    try:
        proc = subprocess.run(
            list(argv), capture_output=True, text=True, timeout=timeout, check=False, shell=False
        )
    except FileNotFoundError:
        return 127, "", f"{argv[0]}: command not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"{argv[0]}: timed out after {timeout:g}s"
    return proc.returncode, proc.stdout, proc.stderr
