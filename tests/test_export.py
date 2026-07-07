import json

from netmapper import export, viz_html
from netmapper.models import Device, Edge, RunMeta
from netmapper.topology import layout


def _sample():
    devices = {
        "10.0.0.1": Device(mgmt_ip="10.0.0.1", hostname="core-vsp-1", status="ok",
                           model="8284XSQ", device_type="switch"),
        "10.0.0.2": Device(mgmt_ip="10.0.0.2", hostname="edge-fw-1", status="ok",
                           device_type="firewall"),
    }
    edges = [Edge(a="10.0.0.1", a_if="1/1", b="10.0.0.2", b_if="port1",
                  source="lldp", confidence=1.0, sources=["lldp"],
                  reported_by=["10.0.0.1"])]
    return devices, edges


def test_dot():
    devices, edges = _sample()
    dot = export.to_dot(devices, edges)
    assert "core-vsp-1" in dot and '"10.0.0.1" -- "10.0.0.2"' in dot
    assert "1/1 - port1" in dot


def test_mermaid():
    devices, edges = _sample()
    mm = export.to_mermaid(devices, edges)
    assert mm.startswith("graph TD")
    assert "core-vsp-1" in mm and "---" in mm


def test_graphml(tmp_path):
    devices, edges = _sample()
    out = tmp_path / "t.graphml"
    export.to_graphml(devices, edges, out)
    text = out.read_text()
    assert "graphml" in text and "core-vsp-1" in text


def test_json():
    devices, edges = _sample()
    meta = RunMeta(run_id="r", started="s")
    data = json.loads(export.to_json(meta, devices, edges))
    assert data["run"]["run_id"] == "r"
    assert len(data["devices"]) == 2 and len(data["edges"]) == 1


def test_html_is_self_contained():
    devices, edges = _sample()
    meta = RunMeta(run_id="r", started="s", seeds=["10.0.0.1"])
    html = viz_html.build_html(meta, devices, edges, [], layout(devices, edges, iterations=10))
    assert "core-vsp-1" in html
    assert "__DATA__" not in html
    # no external fetches: no http(s) URLs outside the w3.org SVG namespace constant
    import re
    urls = [u for u in re.findall(r"https?://[^\s\"']+", html) if "w3.org" not in u]
    assert urls == []
