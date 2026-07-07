"""Parser tests for the flagship Extreme VOSS plugin."""
from netmapper.plugins import extreme_voss as v


def test_sys_info(fx):
    info = v.parse_sys_info(fx("voss_sys_info.txt"))
    assert info["hostname"] == "core-vsp-1"
    assert info["model"] == "8284XSQ"
    assert info["sw_version"] == "8.10.1.0"
    assert info["serial"] == "14JP512E0009"
    assert "VSP-8284XSQ" in info["sys_descr"]


def test_lldp_neighbor(fx):
    cands = v.parse_lldp_neighbor(fx("voss_lldp_neighbor.txt"))
    assert len(cands) == 2
    a, b = cands
    assert a.local_interface == "1/1"
    assert a.remote_hostname == "access-vsp-1"
    assert a.remote_mac == "b0:ad:aa:4c:74:00"
    assert a.remote_interface == "Port 1/5"
    assert a.remote_ip == "10.20.0.11"
    assert a.source == "lldp" and a.confidence == 1.0
    assert b.remote_hostname == "edge-exos-1"
    assert b.remote_ip == ""  # no mgmt address TLV in second block


def test_isis_adjacencies(fx):
    cands = v.parse_isis_adjacencies(fx("voss_isis_adjacencies.txt"))
    assert len(cands) == 2  # DOWN adjacency ignored
    assert cands[0].local_interface == "1/3"
    assert cands[0].remote_hostname == "access-vsp-1"
    assert cands[0].remote_mac == "b0:ad:aa:4c:74:00"
    assert cands[0].source == "isis" and "spbm" in cands[0].tags
    assert cands[1].local_interface == "Mlt2"
    assert cands[1].remote_hostname == "core-vsp-2"


def test_virtual_ist(fx):
    cands = v.parse_virtual_ist(fx("voss_virtual_ist.txt"))
    assert len(cands) == 1
    assert cands[0].remote_ip == "192.168.255.2"
    assert set(cands[0].tags) >= {"vist", "smlt"}
    assert cands[0].source == "vist"


def test_interfaces(fx):
    ifaces = v.parse_interfaces(fx("voss_interfaces.txt"))
    assert [i.name for i in ifaces] == ["1/1", "1/2", "1/3", "2/1"]
    assert ifaces[0].mac == "b0:ad:aa:4c:74:01"
    assert (ifaces[0].admin_status, ifaces[0].oper_status) == ("up", "up")
    assert (ifaces[1].admin_status, ifaces[1].oper_status) == ("up", "down")
    assert (ifaces[3].admin_status, ifaces[3].oper_status) == ("down", "down")
    assert ifaces[0].description == "40GbCR4"


def test_ip_route(fx):
    routes = v.parse_ip_route(fx("voss_ip_route.txt"))
    assert len(routes) == 3
    assert routes[0].prefix == "0.0.0.0/0"
    assert routes[0].next_hop == "10.0.255.1"
    assert routes[0].protocol == "STAT"
    assert routes[1].prefix == "10.20.0.0/24"
    assert routes[1].protocol == "OSPF"
    assert routes[2].protocol == "LOC"


def test_ip_arp(fx):
    arp = v.parse_ip_arp(fx("voss_ip_arp.txt"))
    assert len(arp) == 3
    assert arp[0].ip == "10.0.0.11" and arp[0].mac == "b0:ad:aa:4c:74:00"
    assert arp[0].port == "1/1"
    assert arp[1].port == "Mlt2"


def test_fdb(fx):
    fdb = v.parse_fdb(fx("voss_fdb.txt"))
    # 'self' entry skipped
    assert len(fdb) == 2
    assert fdb[0].vlan == "20" and fdb[0].mac == "3c:ec:ef:12:34:56"
    assert fdb[0].port == "1/7"
    assert fdb[1].port == "Mlt2"
