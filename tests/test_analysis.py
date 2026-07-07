from netmapper.analysis import analyze
from netmapper.models import Device, Edge, Interface, NeighborCandidate
from netmapper.topology import build_edges


def _rules(findings):
    return {f.rule for f in findings}


def test_unreachable_seed_is_critical():
    devices = {"10.0.0.9": Device(mgmt_ip="10.0.0.9", status="unreachable", depth=0)}
    fs = analyze(devices, [])
    f = next(f for f in fs if f.rule == "unreachable")
    assert f.severity == "critical"
    assert f.recommendation


def test_auth_failed_at_depth_is_warning():
    devices = {"10.0.0.9": Device(mgmt_ip="10.0.0.9", status="auth_failed", depth=2)}
    fs = analyze(devices, [])
    f = next(f for f in fs if f.rule == "unreachable")
    assert f.severity == "warning"


def test_asymmetric_lldp():
    a = Device(mgmt_ip="10.0.0.1", hostname="a", status="ok")
    a.neighbors = [NeighborCandidate(local_interface="1/1", remote_hostname="b", source="lldp")]
    b = Device(mgmt_ip="10.0.0.2", hostname="b", status="ok")
    # b has LLDP data but does NOT report a
    b.neighbors = [NeighborCandidate(local_interface="1/5", remote_hostname="c", source="lldp")]
    devices = {"10.0.0.1": a, "10.0.0.2": b}
    edges, stubs = build_edges(devices)
    devices.update(stubs)
    fs = analyze(devices, edges)
    assert "asymmetric-lldp" in _rules(fs)


def test_spof_articulation_point():
    # a - m - b : m is an articulation point
    devices = {
        ip: Device(mgmt_ip=ip, hostname=h, status="ok", device_type="switch")
        for ip, h in [("10.0.0.1", "a"), ("10.0.0.2", "m"), ("10.0.0.3", "b")]
    }
    edges = [
        Edge(a="10.0.0.1", a_if="1", b="10.0.0.2", b_if="1", source="lldp", confidence=1.0,
             sources=["lldp"], reported_by=["10.0.0.1", "10.0.0.2"]),
        Edge(a="10.0.0.2", a_if="2", b="10.0.0.3", b_if="1", source="lldp", confidence=1.0,
             sources=["lldp"], reported_by=["10.0.0.2", "10.0.0.3"]),
    ]
    fs = [f for f in analyze(devices, edges) if f.rule == "single-point-of-failure"]
    assert any("10.0.0.2" in f.affected and f.severity == "warning" for f in fs)


def test_isolated_segment():
    devices = {
        "10.0.0.1": Device(mgmt_ip="10.0.0.1", status="ok"),
        "10.0.0.2": Device(mgmt_ip="10.0.0.2", status="ok"),
        "10.0.9.1": Device(mgmt_ip="10.0.9.1", status="ok"),
    }
    edges = [Edge(a="10.0.0.1", a_if="", b="10.0.0.2", b_if="", source="lldp",
                  confidence=1.0, sources=["lldp"], reported_by=["10.0.0.1"])]
    fs = analyze(devices, edges)
    assert "isolated-segment" in _rules(fs)


def test_duplicate_hostname_and_ip():
    devices = {
        "10.0.0.1": Device(mgmt_ip="10.0.0.1", hostname="dup", status="ok",
                           interfaces=[Interface(name="v1", ips=["192.168.9.1/24"])]),
        "10.0.0.2": Device(mgmt_ip="10.0.0.2", hostname="dup", status="ok",
                           interfaces=[Interface(name="v1", ips=["192.168.9.1/24"])]),
    }
    fs = analyze(devices, [])
    assert "duplicate-identity" in _rules(fs)
    assert "duplicate-ip" in _rules(fs)


def test_interface_issue_on_known_link():
    a = Device(mgmt_ip="10.0.0.1", hostname="a", status="ok",
               interfaces=[Interface(name="1/1", admin_status="up", oper_status="down")])
    b = Device(mgmt_ip="10.0.0.2", hostname="b", status="ok")
    edges = [Edge(a="10.0.0.1", a_if="1/1", b="10.0.0.2", b_if="1/9", source="fdb",
                  confidence=0.7, sources=["fdb"], reported_by=["10.0.0.1"])]
    fs = analyze({"10.0.0.1": a, "10.0.0.2": b}, edges)
    hits = [f for f in fs if f.rule == "interface-issue" and f.severity == "warning"]
    assert hits and "10.0.0.1" in hits[0].affected


def test_topology_changes():
    old = {"10.0.0.1": Device(mgmt_ip="10.0.0.1", hostname="a", status="ok"),
           "10.0.0.2": Device(mgmt_ip="10.0.0.2", hostname="gone", status="ok")}
    new = {"10.0.0.1": Device(mgmt_ip="10.0.0.1", hostname="a", status="ok"),
           "10.0.0.3": Device(mgmt_ip="10.0.0.3", hostname="fresh", status="ok")}
    fs = [f for f in analyze(new, [], prev=(old, [])) if f.rule == "topology-change"]
    titles = " | ".join(f.title for f in fs)
    assert "disappeared" in titles and "new device" in titles


def test_missing_neighbor_stub():
    a = Device(mgmt_ip="10.0.0.1", hostname="a", status="ok")
    a.neighbors = [NeighborCandidate(local_interface="1/9", remote_hostname="ghost",
                                     source="lldp")]
    devices = {"10.0.0.1": a}
    edges, stubs = build_edges(devices)
    devices.update(stubs)
    fs = analyze(devices, edges)
    f = next(f for f in fs if f.rule == "missing-neighbor")
    assert f.severity == "warning"  # LLDP-claimed -> warning
