"""Lighter parser tests for the secondary vendor plugins."""
from netmapper.plugins import checkpoint as cp
from netmapper.plugins import extreme_universal as xu
from netmapper.plugins import fortigate as fg
from netmapper.plugins import juniper as jn


def test_exos_show_switch(fx):
    info = xu.parse_show_switch(fx("exos_show_switch.txt"))
    assert info == {"hostname": "edge-exos-1", "model": "X465-48T", "sw_version": "31.7.1.4"}


def test_exos_lldp_detailed(fx):
    cands = xu.parse_lldp_detailed(fx("exos_lldp_detailed.txt"))
    assert len(cands) == 2
    assert cands[0].local_interface == "1:3"
    assert cands[0].remote_hostname == "core-vsp-1"
    assert cands[0].remote_mac == "b0:ad:aa:4c:74:00"
    assert cands[0].remote_interface == "Port 1/2"
    assert cands[0].remote_ip == "10.0.0.1"
    assert cands[1].remote_hostname == "cp-gw-1"


def test_junos_version(fx):
    info = jn.parse_show_version(fx("junos_show_version.txt"))
    assert info == {"hostname": "dist-jnp-1", "model": "ex4300-48t",
                    "sw_version": "21.4R3-S1.5"}


def test_junos_lldp(fx):
    cands = jn.parse_lldp_neighbors(fx("junos_lldp.txt"))
    assert len(cands) == 2
    assert cands[0].local_interface == "ge-0/0/47"
    assert cands[0].remote_mac == "b0:ad:aa:4c:74:00"
    assert cands[0].remote_interface == "Port 1/8"
    assert cands[0].remote_hostname == "core-vsp-1"


def test_junos_routes(fx):
    routes = jn.parse_route_terse(fx("junos_route_terse.txt"))
    assert [(r.prefix, r.next_hop, r.protocol) for r in routes] == [
        ("0.0.0.0/0", "10.99.0.1", "static"),
        ("10.20.0.0/24", "10.0.0.1", "ospf"),
    ]


def test_junos_interfaces(fx):
    ifaces = jn.parse_interfaces_terse(fx("junos_int_terse.txt"))
    names = {i.name: i for i in ifaces}
    assert names["ge-0/0/0.0"].ips == ["10.99.0.2/30"]
    assert names["ge-0/0/47"].oper_status == "down"


def test_forti_status(fx):
    info = fg.parse_system_status(fx("forti_status.txt"))
    assert info["model"] == "FortiGate-100F"
    assert info["sw_version"] == "7.2.5"
    assert info["hostname"] == "edge-fw-1"


def test_forti_routes(fx):
    routes = fg.parse_routing_table(fx("forti_route.txt"))
    assert [(r.prefix, r.next_hop, r.protocol, r.interface) for r in routes] == [
        ("0.0.0.0/0", "203.0.113.1", "static", "wan1"),
        ("10.99.0.0/24", "", "connected", "port1"),
        ("10.20.0.0/24", "10.99.0.1", "ospf", "port1"),
    ]


def test_forti_interfaces(fx):
    ifaces = fg.parse_system_interface(fx("forti_interface.txt"))
    names = {i.name: i for i in ifaces}
    assert names["port1"].ips == ["10.99.0.2/24"]
    assert names["port2"].ips == []  # 0.0.0.0 skipped
    assert names["wan1"].oper_status == "up"


def test_forti_arp(fx):
    arp = fg.parse_system_arp(fx("forti_arp.txt"))
    assert arp[0].ip == "10.99.0.1" and arp[0].port == "port1"


def test_cp_routes(fx):
    routes = cp.parse_route(fx("cp_route.txt"))
    assert routes[0].prefix == "0.0.0.0/0"
    assert routes[0].next_hop == "10.99.1.1"
    assert routes[0].protocol == "static"
    assert len(routes) == 3


def test_cp_interfaces(fx):
    ifaces = cp.parse_interfaces_all(fx("cp_interfaces.txt"))
    assert len(ifaces) == 2
    assert ifaces[0].name == "eth0"
    assert ifaces[0].ips == ["10.99.1.2/24"]
    assert ifaces[0].mac == "00:1c:7f:aa:bb:01"
    assert ifaces[0].oper_status == "up"
    assert ifaces[1].oper_status == "down"


def test_cp_version():
    assert cp.parse_version("Product version Check Point Gaia R81.20") == "R81.20"
