"""FortiGate (FortiOS) plugin. LLDP is rare on FortiGates; discovery leans on
routes and ARP, with SNMP LLDP available through the generic MIB path."""
from __future__ import annotations

import ipaddress
import re

from ..models import ArpEntry, Device, Interface, Route, norm_mac
from .base import CollectContext, VendorPlugin

MAC_RE = r"[0-9a-fA-F]{2}(?:[:.-][0-9a-fA-F]{2}){5}"
IP_RE = r"\d+\.\d+\.\d+\.\d+"

PROTO_LETTERS = {"S": "static", "C": "connected", "O": "ospf", "B": "bgp", "R": "rip", "K": "kernel"}


def parse_system_status(text: str) -> dict:
    out: dict[str, str] = {}
    m = re.search(r"Version:\s*(\S+?)\s+v([\d.]+)", text)
    if m:
        out["model"], out["sw_version"] = m.group(1), m.group(2)
    m = re.search(r"Hostname:\s*(\S+)", text)
    if m:
        out["hostname"] = m.group(1)
    m = re.search(r"Serial-Number:\s*(\S+)", text)
    if m:
        out["serial"] = m.group(1)
    return out


def parse_system_interface(text: str) -> list[Interface]:
    ifaces = []
    for line in text.splitlines():
        nm = re.search(r"name:\s*(\S+)", line)
        if not nm:
            continue
        iface = Interface(name=nm.group(1))
        im = re.search(rf"ip:\s*({IP_RE})\s+({IP_RE})", line)
        if im and im.group(1) != "0.0.0.0":
            try:
                net = ipaddress.ip_network(f"{im.group(1)}/{im.group(2)}", strict=False)
                iface.ips.append(f"{im.group(1)}/{net.prefixlen}")
            except ValueError:
                pass
        sm = re.search(r"status:\s*(\S+)", line)
        if sm:
            iface.admin_status = iface.oper_status = sm.group(1)
        ifaces.append(iface)
    return ifaces


def parse_routing_table(text: str) -> list[Route]:
    routes = []
    for line in text.splitlines():
        m = re.match(rf"\s*([A-Z])\*?\s+({IP_RE}/\d+)\s*(.*)", line)
        if not m:
            continue
        rest = m.group(3)
        vm = re.search(rf"via ({IP_RE})", rest)
        im = re.search(r",\s*([A-Za-z]\S*?)(?:,|\s*$)", rest)
        routes.append(Route(prefix=m.group(2), next_hop=vm.group(1) if vm else "",
                            protocol=PROTO_LETTERS.get(m.group(1), m.group(1)),
                            interface=im.group(1) if im else ""))
    return routes


def parse_system_arp(text: str) -> list[ArpEntry]:
    out = []
    for line in text.splitlines():
        m = re.match(rf"\s*({IP_RE})\s+\S+\s+({MAC_RE})\s+(\S+)", line)
        if m:
            out.append(ArpEntry(ip=m.group(1), mac=norm_mac(m.group(2)), port=m.group(3)))
    return out


class FortigatePlugin(VendorPlugin):
    name = "fortigate"
    vendor = "Fortinet"
    netmiko_device_type = "fortinet"
    match_keywords = ("fortigate", "fortios", "fortinet")

    def get_identity(self, device: Device, ctx: CollectContext) -> None:
        info = parse_system_status(ctx.ssh.send("get system status"))
        for k, v in info.items():
            setattr(device, k, v)

    def get_interfaces(self, device: Device, ctx: CollectContext) -> None:
        device.interfaces = parse_system_interface(
            ctx.ssh.send("get system interface", timeout=60))

    def get_routes(self, device: Device, ctx: CollectContext) -> None:
        device.routes = parse_routing_table(
            ctx.ssh.send("get router info routing-table all", timeout=60))

    def get_arp(self, device: Device, ctx: CollectContext) -> None:
        device.arp = parse_system_arp(ctx.ssh.send("get system arp", timeout=60))

    def classify(self, device: Device) -> str:
        return "firewall"
