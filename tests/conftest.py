from __future__ import annotations

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
