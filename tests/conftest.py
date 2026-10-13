from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

INVENTORY = """
devices:
  - name: router
    kind: router
    management_ip: 192.168.1.1
  - name: nas
    kind: nas
    management_ip: 192.168.1.20
subnets:
  - cidr: 192.168.1.0/24
    gateway: 192.168.1.1
"""

CONFIG = """
data_dir: data
targets:
  - name: inventory
    plugin: manual
    options:
      file: inventory.yaml
"""


@pytest.fixture
def lab_dir(tmp_path: Path) -> Path:
    """A directory with a working labwarden.yaml + inventory.yaml."""
    (tmp_path / "inventory.yaml").write_text(INVENTORY, encoding="utf-8")
    (tmp_path / "labwarden.yaml").write_text(CONFIG, encoding="utf-8")
    return tmp_path


WRAPPER = Path(__file__).parent.parent / "deploy" / "ssh" / "labwarden-ssh-wrapper.sh"


@pytest.fixture(scope="session")
def run_wrapper(tmp_path_factory: pytest.TempPathFactory):
    """Run the SSH forced-command wrapper on a command line, without executing anything.

    The test runs a temporary copy in which every ``exec`` is replaced by a stub
    that prints ``ALLOWED <argv>`` and exits 0. So the test sees exactly what
    the wrapper *would* run, and nothing ever runs. (An empty PATH isn't
    enough: on Windows, Git's sh still finds curl.exe and ping.exe in System32.)
    Refused commands exit 126 as usual.
    """
    sh = shutil.which("sh")
    if sh is None:
        pytest.skip("needs a POSIX sh")
    lines = WRAPPER.read_text(encoding="utf-8").splitlines(keepends=True)
    patched, replaced = [], 0
    for line in lines:
        if not line.lstrip().startswith("#") and "exec " in line:
            replaced += line.count("exec ")
            line = line.replace("exec ", "allowed ")
        patched.append(line)
        if line == "set -eu\n":
            patched.append('allowed() { printf "ALLOWED %s\n" "$*"; exit 0; }\n')
    assert replaced >= 13, "the wrapper's exec lines changed shape; update this fixture"
    copy = tmp_path_factory.mktemp("wrapper") / "wrapper.sh"
    copy.write_text("".join(patched), encoding="utf-8", newline="\n")

    def run(command: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sh, str(copy)],
            # PATH empty too, so `logger` in the refusal path doesn't run either.
            env={"SSH_ORIGINAL_COMMAND": command, "PATH": "/nonexistent"},
            capture_output=True,
            text=True,
            timeout=30,
        )

    return run
