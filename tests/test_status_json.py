"""docs/status.json is published on the portfolio site, so keep it valid and free of lab details."""

from __future__ import annotations

import json
import re
from pathlib import Path

STATUS = Path(__file__).parent.parent / "docs" / "status.json"
STATES = {"done", "in_progress", "planned"}


def test_status_json_is_well_formed() -> None:
    data = json.loads(STATUS.read_text(encoding="utf-8"))
    numbers = [p["number"] for p in data["phases"]]
    assert numbers == sorted(numbers)
    assert data["current_phase"] in numbers
    for phase in data["phases"]:
        assert phase["state"] in STATES
        for step in phase.get("steps", []):
            assert step["state"] in STATES
    current = next(p for p in data["phases"] if p["number"] == data["current_phase"])
    assert current["state"] == "in_progress"


def test_status_json_has_no_ip_addresses() -> None:
    text = STATUS.read_text(encoding="utf-8")
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", text)
