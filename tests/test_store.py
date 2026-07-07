import pytest

from netmapper.models import Device, Edge, Finding, RunMeta
from netmapper.store import RunStore, StoreError


def _sample():
    meta = RunMeta(run_id="2026-07-06T10-00-00", started="2026-07-06T10:00:00",
                   seeds=["10.0.0.1"], max_depth=2, stats={"devices": 2})
    devices = {
        "10.0.0.1": Device(mgmt_ip="10.0.0.1", hostname="core-vsp-1", status="ok",
                           vendor="Extreme Networks", sw_version="8.10.1.0"),
        "10.0.0.2": Device(mgmt_ip="10.0.0.2", hostname="core-vsp-2", status="ok"),
    }
    edges = [Edge(a="10.0.0.1", a_if="1/1", b="10.0.0.2", b_if="1/1",
                  source="lldp", confidence=1.0, sources=["lldp", "isis"],
                  reported_by=["10.0.0.1", "10.0.0.2"], tags=["spbm"])]
    return meta, devices, edges


def test_roundtrip(tmp_path):
    store = RunStore(tmp_path)
    meta, devices, edges = _sample()
    store.save_run(meta, devices, edges)

    meta2, devices2, edges2 = store.load_run("latest")
    assert meta2.run_id == meta.run_id
    assert meta2.stats == {"devices": 2}
    assert set(devices2) == {"10.0.0.1", "10.0.0.2"}
    assert devices2["10.0.0.1"].hostname == "core-vsp-1"
    assert edges2[0].sources == ["lldp", "isis"]
    assert edges2[0].tags == ["spbm"]


def test_findings_roundtrip(tmp_path):
    store = RunStore(tmp_path)
    meta, devices, edges = _sample()
    store.save_run(meta, devices, edges)
    assert store.load_findings("latest") is None
    store.save_findings(meta.run_id, [Finding(rule="x", severity="warning", title="t")])
    loaded = store.load_findings("latest")
    assert loaded and loaded[0].severity == "warning"


def test_resolve(tmp_path):
    store = RunStore(tmp_path)
    for rid in ("2026-07-01T09-00-00", "2026-07-02T09-00-00"):
        meta, devices, edges = _sample()
        meta.run_id = rid
        store.save_run(meta, devices, edges)
    assert store.resolve("latest") == "2026-07-02T09-00-00"
    assert store.resolve("2026-07-01") == "2026-07-01T09-00-00"
    with pytest.raises(StoreError):
        store.resolve("2026-07")  # ambiguous
    with pytest.raises(StoreError):
        RunStore(tmp_path / "empty").resolve("latest")
