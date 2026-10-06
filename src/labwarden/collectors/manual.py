"""Manual inventory: things you declare by hand in a YAML file.

Some facts can't be discovered: what model your unmanaged switch is, which
port the NAS is plugged into, what the Raspberry Pi is *for*. This collector
reads them from a YAML file whose top-level keys are LabModel collections::

    devices:
      - name: pihole
        kind: server
        management_ip: 192.168.1.2
        roles: [dns, dhcp]
        hardware: {cpu: "Raspberry Pi 4", memory_mb: 4096, nic_count: 1}
    subnets:
      - cidr: 192.168.1.0/24
        name: home
        gateway: 192.168.1.1
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict

from labwarden.collectors.base import Collector
from labwarden.model.lab import LabModel


class ManualOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file: Path


class ManualCollector(Collector):
    plugin = "manual"
    description = "Hand-written inventory from a YAML file (devices, subnets, VLANs, links, ...)."
    provides = frozenset(LabModel.kinds()) - {"log_events"}
    Options = ManualOptions

    def collect(self) -> LabModel:
        path = self.options.file
        if not path.is_absolute():
            path = self.base_dir / path
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError(f"{path}: expected a mapping of collection name -> list")
        return LabModel.model_validate(data)
