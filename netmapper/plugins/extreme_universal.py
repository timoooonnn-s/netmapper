"""Extreme Universal hardware running Switch Engine (EXOS syntax).

Universal switches booted as Fabric Engine speak VOSS and match the
extreme_voss plugin via fingerprint instead.
"""
from __future__ import annotations

import re

from ..models import ArpEntry, Device, NeighborCandidate, Route, norm_mac
from .base import CollectContext, VendorPlugin

MAC_RE = r"[0-9a-fA-F]{2}(?:[:.-][0-9a-fA-F]{2}){5}"
IP_RE = r"\d+\.\d+\.\d+\.\d+"


def parse_show_switch(text: str) -> dict:
    out: dict[str, str] = {}
    for key, pat in (
        ("hostname", r"SysName:\s*(\S+)"),
        ("model", r"System Type:\s*(\S+)"),
        ("sw_version", r"Primary ver:\s*(\S+)"),
    ):
        m = re.search(pat, text)
        if m:
            out[key] = m.group(1).strip()
    return out


def parse_lldp_detailed(text: str) -> list[NeighborCandidate]:
    cands = []
    parts = re.split(r"(?m)^LLDP Port (\S+) detected", text)
    # parts = [prefix, port1, body1, port2, body2, ...]
    for port, body in zip(parts[1::2], parts[2::2]):
        c = NeighborCandidate(local_interface=port, source="lldp")
        m = re.search(rf"Chassis ID\s*:\s*({MAC_RE})", body)
        if m:
            c.remote_mac = norm_mac(m.group(1))
        m = re.search(r"Port Description\s*:\s*\"?([^\"\n]+)", body)
        if m:
            c.remote_interface = m.group(1).strip()
        elif (m := re.search(r"Port ID\s*:\s*\"?([^\"\n]+)", body)):
            c.remote_interface = m.group(1).strip()
        m = re.search(r"System Name\s*:\s*\"?([^\"\n]+)", body)
        if m:
            c.remote_hostname = m.group(1).strip().strip('"')
        m = re.search(rf"Management Address\s*:\s*({IP_RE})", body)
        if m:
            c.remote_ip = m.group(1)
        if c.remote_hostname or c.remote_mac:
            cands.append(c)
    return cands


def parse_iproute(text: str) -> list[Route]:
    routes = []
    for line in text.splitlines():
        m = re.search(rf"([\d.]+/\d+)\s+({IP_RE})?", line)
        if not m or "/" not in (m.group(1) or ""):
            continue
        first = line.split()[0] if line.split() else ""
        routes.append(Route(prefix=m.group(1), next_hop=m.group(2) or "",
                            protocol=first.strip("#*")))
    return routes


def parse_iparp(text: str) -> list[ArpEntry]:
    out = []
    for line in text.splitlines():
        m = re.match(rf"\s*({IP_RE})\s+.*?({MAC_RE})", line)
        if m:
            out.append(ArpEntry(ip=m.group(1), mac=norm_mac(m.group(2))))
    return out


class ExtremeUniversalPlugin(VendorPlugin):
    name = "extreme_universal"
    vendor = "Extreme Networks"
    netmiko_device_type = "extreme_exos"
    match_keywords = ("extremexos", "exos", "switch engine", "summit", "x435", "x465", "5320", "5420", "5520")

    def get_identity(self, device: Device, ctx: CollectContext) -> None:
        info = parse_show_switch(ctx.ssh.send("show switch"))
        device.hostname = info.get("hostname", device.hostname)
        device.model = info.get("model", device.model)
        device.sw_version = info.get("sw_version", device.sw_version)

    def get_lldp(self, device: Device, ctx: CollectContext) -> None:
        device.neighbors += parse_lldp_detailed(
            ctx.ssh.send("show lldp neighbors detailed", timeout=60))

    def get_routes(self, device: Device, ctx: CollectContext) -> None:
        device.routes = parse_iproute(ctx.ssh.send("show iproute", timeout=60))

    def get_arp(self, device: Device, ctx: CollectContext) -> None:
        device.arp = parse_iparp(ctx.ssh.send("show iparp", timeout=60))

    def classify(self, device: Device) -> str:
        return "switch"
