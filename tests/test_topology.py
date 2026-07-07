from netmapper.models import Device, Edge, Interface, NeighborCandidate
from netmapper.topology import build_edges, build_graph, diff_runs, layout


def _two_switches():
    a = Device(mgmt_ip="10.0.0.1", hostname="core-vsp-1", status="ok")
    a.neighbors = [NeighborCandidate(local_interface="1/1", remote_hostname="core-vsp-2",
                                     remote_mac="0e:4a:10:ff:80:01", remote_interface="1/1",
                                     source="lldp")]
    b = Device(mgmt_ip="10.0.0.2", hostname="core-vsp-2", status="ok")
    b.neighbors = [NeighborCandidate(local_interface="1/1", remote_hostname="core-vsp-1",
                                     remote_interface="1/1", source="lldp"),
                   NeighborCandidate(local_interface="1/1", remote_hostname="core-vsp-1",
                                     source="isis", tags=["spbm"])]
    return {"10.0.0.1": a, "10.0.0.2": b}


def test_bidirectional_lldp_merges_to_one_edge():
    devices = _two_switches()
    edges, stubs = build_edges(devices)
    assert stubs == {}
    assert len(edges) == 1
    e = edges[0]
    assert {e.a, e.b} == {"10.0.0.1", "10.0.0.2"}
    assert e.a_if == "1/1" and e.b_if == "1/1"
    assert set(e.sources) == {"lldp", "isis"}
    assert set(e.reported_by) == {"10.0.0.1", "10.0.0.2"}
    assert "spbm" in e.tags
    assert e.confidence == 1.0


def test_unresolved_neighbor_becomes_stub():
    a = Device(mgmt_ip="10.0.0.1", hostname="core-vsp-1", status="ok")
    a.neighbors = [NeighborCandidate(local_interface="1/9", remote_hostname="mystery-sw",
                                     source="lldp")]
    edges, stubs = build_edges({"10.0.0.1": a})
    assert len(edges) == 1 and len(stubs) == 1
    stub = next(iter(stubs.values()))
    assert stub.status == "stub" and stub.hostname == "mystery-sw"


def test_resolution_by_interface_ip_and_mac():
    a = Device(mgmt_ip="10.0.0.1", hostname="r1", status="ok")
    a.neighbors = [NeighborCandidate(remote_ip="192.168.1.2", source="route"),
                   NeighborCandidate(remote_mac="aa:bb:cc:dd:ee:ff", source="fdb")]
    b = Device(mgmt_ip="10.0.0.2", hostname="r2", status="ok",
               interfaces=[Interface(name="vlan10", ips=["192.168.1.2/24"],
                                     mac="aa:bb:cc:dd:ee:ff")])
    edges, stubs = build_edges({"10.0.0.1": a, "10.0.0.2": b})
    assert stubs == {}
    assert len(edges) == 1  # both claims resolve to the same node pair and merge
    assert set(edges[0].sources) == {"route", "fdb"}


def test_no_self_loops():
    a = Device(mgmt_ip="10.0.0.1", hostname="r1", status="ok")
    a.neighbors = [NeighborCandidate(remote_ip="10.0.0.1", source="arp")]
    edges, stubs = build_edges({"10.0.0.1": a})
    assert edges == [] and stubs == {}


def test_layout_and_graph():
    devices = _two_switches()
    edges, _ = build_edges(devices)
    g = build_graph(devices, edges)
    assert g.number_of_nodes() == 2 and g.number_of_edges() == 1
    pos = layout(devices, edges, iterations=30)
    assert set(pos) == set(devices)
    (x1, y1), (x2, y2) = pos.values()
    assert (x1, y1) != (x2, y2)


def test_diff_runs():
    old = _two_switches()
    old_edges, _ = build_edges(old)
    new = _two_switches()
    new["10.0.0.3"] = Device(mgmt_ip="10.0.0.3", hostname="new-sw", status="ok")
    new["10.0.0.1"].sw_version = "9.0.0.0"
    old["10.0.0.1"].sw_version = "8.10.1.0"
    new_edges, _ = build_edges(new)
    d = diff_runs(old, old_edges, new, new_edges)
    assert d["added_devices"] == ["10.0.0.3"]
    assert d["removed_devices"] == []
    assert d["version_changes"] == [("10.0.0.1", "8.10.1.0", "9.0.0.0")]
