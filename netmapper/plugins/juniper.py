"""Juniper Junos plugin (EX/QFX/MX/SRX)."""
from __future__ import annotations

import re

from ..models import Device, Interface, NeighborCandidate, Route, norm_mac
from .base import CollectContext, VendorPlugin

MAC_RE = r"[0-9a-fA-F]{2}(?:[:.]?[0-9a-fA-F]{2}){5}"
IP_RE = r"\d+\.\d+\.\d+\.\d+"

PROTO_LETTERS = {"S": "static", "O": "ospf", "B": "bgp", "D": "direct",
                 "L": "local", "I": "isis", "R": "rip", "A": "aggregate"}


def parse_show_version(text: str) -> dict:
    out: dict[str, str] = {}
    for key, pat in (
        ("hostname", r"Hostname:\s*(\S+)"),
        ("model", r"Model:\s*(\S+)"),
        ("sw_version", r"Junos:\s*(\S+)"),
    ):
        m = re.search(pat, text)
        if m:
            out[key] = m.group(1)
    return out


def parse_lldp_neighbors(text: str) -> list[NeighborCandidate]:
    cands = []
    for line in text.splitlines():
        cols = re.split(r"\s{2,}", line.strip())
        if len(cols) < 5 or cols[0].lower().startswith("local"):
            continue
        mac = norm_mac(cols[2])
        if not mac:
            continue
        cands.append(NeighborCandidate(
            local_interface=cols[0].split(".")[0],
            remote_mac=mac,
            remote_interface=cols[3],
            remote_hostname=cols[4],
            source="lldp",
        ))
    return cands


def parse_route_terse(text: str) -> list[Route]:
    routes = []
    cur_prefix, cur_proto = "", ""
    for line in text.splitlines():
        pm = re.search(rf"({IP_RE}/\d+)", line)
        if pm:
            cur_prefix = pm.group(1)
            after = line[pm.end():].split()
            letter = next((t for t in after if len(t) == 1 and t.isalpha() and t.isupper()), "")
            cur_proto = PROTO_LETTERS.get(letter, letter)
        nm = re.search(rf">({IP_RE})", line)
        if nm and cur_prefix:
            routes.append(Route(prefix=cur_prefix, next_hop=nm.group(1), protocol=cur_proto))
    return routes


def parse_interfaces_terse(text: str) -> list[Interface]:
    ifaces = []
    for line in text.splitlines():
        m = re.match(r"(\S+)\s+(up|down)\s+(up|down)(?:\s+(\S+)\s+(\S+))?", line.strip())
        if not m:
            continue
        iface = Interface(name=m.group(1), admin_status=m.group(2), oper_status=m.group(3))
        if m.group(4) == "inet" and m.group(5):
            iface.ips.append(m.group(5))
        ifaces.append(iface)
    return ifaces


class JuniperPlugin(VendorPlugin):
    name = "juniper_junos"
    vendor = "Juniper"
    netmiko_device_type = "juniper_junos"
    match_keywords = ("juniper", "junos")

    def get_identity(self, device: Device, ctx: CollectContext) -> None:
        info = parse_show_version(ctx.ssh.send("show version"))
        device.hostname = info.get("hostname", device.hostname)
        device.model = info.get("model", device.model)
        device.sw_version = info.get("sw_version", device.sw_version)

    def get_interfaces(self, device: Device, ctx: CollectContext) -> None:
        device.interfaces = parse_interfaces_terse(
            ctx.ssh.send("show interfaces terse", timeout=60))

    def get_lldp(self, device: Device, ctx: CollectContext) -> None:
        device.neighbors += parse_lldp_neighbors(ctx.ssh.send("show lldp neighbors"))

    def get_routes(self, device: Device, ctx: CollectContext) -> None:
        device.routes = parse_route_terse(ctx.ssh.send("show route terse", timeout=60))

    def classify(self, device: Device) -> str:
        model = device.model.lower()
        if model.startswith("srx"):
            return "firewall"
        if model.startswith(("ex", "qfx")):
            return "switch"
        return "router"
