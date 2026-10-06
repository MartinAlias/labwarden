from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from labwarden.model import LabModel, SnapshotStore, diff_models
from labwarden.model.entities import Container, Device, PortMapping, Vlan


def _model() -> LabModel:
    return LabModel.model_validate(
        {
            "devices": [
                {"name": "router", "kind": "router", "management_ip": "192.168.1.1"},
                {"name": "nas", "kind": "nas", "management_ip": "192.168.1.20"},
            ],
            "subnets": [{"cidr": "192.168.1.0/24", "gateway": "192.168.1.1"}],
        }
    )


def test_validation_rejects_bad_values() -> None:
    with pytest.raises(ValidationError):
        Vlan(vlan_id=5000)
    with pytest.raises(ValidationError):
        Device(name="x", management_ip="not-an-ip")
    with pytest.raises(ValidationError):
        Device(name="x", unexpected_field=1)


def test_entity_keys() -> None:
    assert Device(name="nas").key() == ("nas",)
    assert Container(host="srv", name="web", image="nginx").key() == ("srv", "web")


def test_port_mapping_exposure() -> None:
    assert PortMapping(container_port=80, host_port=8080).is_exposed_on_all_interfaces()
    assert PortMapping(
        container_port=80, host_port=8080, host_ip="0.0.0.0"
    ).is_exposed_on_all_interfaces()
    assert not PortMapping(
        container_port=80, host_port=8080, host_ip="127.0.0.1"
    ).is_exposed_on_all_interfaces()
    assert not PortMapping(container_port=80).is_exposed_on_all_interfaces()


def test_merge_keeps_first_and_stamps_source() -> None:
    a = _model()
    a.stamp_source("first")
    b = LabModel(devices=[Device(name="nas", kind="server"), Device(name="pihole")])
    b.stamp_source("second")
    a.merge(b)

    assert [d.name for d in a.devices] == ["router", "nas", "pihole"]
    assert a.device("nas").kind == "nas"
    assert a.device("nas").source == "first"
    assert a.device("pihole").source == "second"


def test_diff_added_removed_changed() -> None:
    before = _model()
    after = _model()
    after.devices = [d for d in after.devices if d.name != "router"]
    after.device("nas").management_ip = "192.168.1.21"
    after.devices.append(Device(name="pihole"))
    after.stamp_source("ignored-in-diff")

    result = diff_models(before, after)
    summary = {(c.status, c.label()) for c in result.changes}
    assert summary == {
        ("added", "devices[pihole]"),
        ("removed", "devices[router]"),
        ("changed", "devices[nas]"),
    }
    (changed,) = result.by_status("changed")
    assert [(f.field, f.before, f.after) for f in changed.changes] == [
        ("management_ip", "192.168.1.20", "192.168.1.21")
    ]


def test_diff_identical_is_empty() -> None:
    assert diff_models(_model(), _model()).is_empty


def test_store_roundtrip(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "db" / "snapshots.db")
    first = store.save(_model(), label="one", taken_at=datetime(2026, 1, 1, tzinfo=UTC))
    second = store.save(LabModel(), errors={"pihole": "timeout"})

    assert store.latest().id == second
    assert store.latest(offset=1).id == first
    assert store.latest(offset=2) is None
    assert store.get(first).model == _model()
    assert store.get(first).label == "one"
    assert store.get(999) is None
    assert [s.id for s in store.history()] == [second, first]
    assert store.history()[0].errors == {"pihole": "timeout"}
