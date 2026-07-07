"""Extreme VSP / VOSS (Fabric Engine) plugin - the flagship platform.

Beyond the standard sources, this plugin understands SPBM fabric adjacencies
(show isis adjacencies) and vIST/SMLT peering (show virtual-ist), so fabric
links are first-class edges instead of anomalies.

All parsing is regex-based against `terminal more disable`-style output; the
exact column layouts vary slightly between VOSS releases, so parsers key on
stable tokens (IPs, MACs, port numbers) rather than column positions.
"""
from __future__ import annotations

import ipaddress
import re

from ..models import ArpEntry, Device, FdbEntry, Interface, NeighborCandidate, Route, norm_mac
from .base import CollectContext, VendorPlugin

MAC_RE = r"[0-9a-fA-F]{2}(?:[:.-][0-9a-fA-F]{2}){5}"
PORT_RE = r"\d+/\d+(?:/\d+)?"
IP_RE = r"\d+\.\d+\.\d+\.\d+"

ROUTE_PROTOCOLS = {"LOC", "STAT", "STATIC", "OSPF", "BGP", "RIP", "ISIS", "SPBM", "COM", "DIR"}


def parse_sys_info(text: str) -> dict:
    out: dict[str, str] = {}
    for key, pat in (
        ("sys_descr", r"SysDescr\s*:\s*(.+)"),
        ("hostname", r"SysName\s*:\s*(\S+)"),
        ("model", r"Chassis\s*:\s*(\S+)"),
        ("serial", r"Serial#?\s*:\s*(\S+)"),
    ):
        m = re.search(pat, text)
        if m:
            out[key] = m.group(1).strip()
    sd = out.get("sys_descr", "")
    m = re.search(r"\((\d[\w.]*)\)", sd)
    if m:
        out["sw_version"] = m.group(1)
    if "model" not in out and sd:
        out["model"] = sd.split()[0]
    return out


def parse_lldp_neighbor(text: str) -> list[NeighborCandidate]:
    cands = []
    for block in re.split(r"(?m)^(?=Port:)", text):
        m = re.match(r"Port:\s*(\S+)", block)
        if not m:
            continue
        c = NeighborCandidate(local_interface=m.group(1), source="lldp")
        mm = re.search(rf"ChassisId\s*:.*?({MAC_RE})", block)
        if mm:
            c.remote_mac = norm_mac(mm.group(1))
        mm = re.search(r"SysName\s*:\s*(.+)", block)
        if mm:
            c.remote_hostname = mm.group(1).strip()
        mm = re.search(r"PortDescr?\s*:\s*(.+)", block)
        if mm:
            c.remote_interface = mm.group(1).strip()
        else:
            mm = re.search(r"PortId\s*:\s*(?:MAC Address\s*)?(.+)", block)
            if mm:
                c.remote_interface = mm.group(1).strip()
        mm = re.search(r"SysDescr\s*:\s*(.+)", block)
        if mm:
            c.remote_descr = mm.group(1).strip()
        mm = re.search(rf"Address\s*:\s*({IP_RE})", block)
        if mm:
            c.remote_ip = mm.group(1)
        if c.remote_hostname or c.remote_mac:
            cands.append(c)
    return cands


def parse_isis_adjacencies(text: str) -> list[NeighborCandidate]:
    """SPBM fabric adjacencies; last column is the fabric peer's hostname."""
    cands = []
    for line in text.splitlines():
        m = re.match(
            r"\s*(\S+)\s+\d\s+(UP|INIT|DOWN)\s+.*?"
            r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+(\S+)\s*$",
            line,
        )
        if m and m.group(2) == "UP":
            cands.append(NeighborCandidate(
                local_interface=m.group(1).removeprefix("Port"),
                remote_mac=norm_mac(m.group(3)),
                remote_hostname=m.group(4),
                source="isis",
                tags=["spbm"],
            ))
    return cands


def parse_virtual_ist(text: str) -> list[NeighborCandidate]:
    for line in text.splitlines():
        m = re.match(rf"\s*({IP_RE})\s+(\d+)\s+\S+\s+(\S+)", line)
        if m:
            return [NeighborCandidate(
                local_interface=f"vIST vlan {m.group(2)}",
                remote_ip=m.group(1),
                source="vist",
                tags=["vist", "smlt"],
            )]
    return []


def parse_interfaces(text: str) -> list[Interface]:
    ifaces = []
    for line in text.splitlines():
        if not re.match(rf"\s*{PORT_RE}\s", line):
            continue
        toks = line.split()
        iface = Interface(name=toks[0])
        mm = re.search(rf"({MAC_RE})", line)
        if mm:
            iface.mac = norm_mac(mm.group(1))
        updown = [t.lower() for t in toks if t.lower() in ("up", "down", "testing")]
        if len(updown) >= 2:
            iface.admin_status, iface.oper_status = updown[-2], updown[-1]
        elif updown:
            iface.admin_status = iface.oper_status = updown[0]
        if len(toks) > 2 and not re.fullmatch(MAC_RE, toks[2]):
            iface.description = toks[2]
        ifaces.append(iface)
    return ifaces


def parse_ip_route(text: str, vrf: str = "GlobalRouter") -> list[Route]:
    routes = []
    for line in text.splitlines():
        toks = line.split()
        if len(toks) < 3:
            continue
        if not (re.fullmatch(IP_RE, toks[0]) and re.fullmatch(IP_RE, toks[1])):
            continue
        try:
            prefix = str(ipaddress.ip_network(f"{toks[0]}/{toks[1]}", strict=False))
        except ValueError:
            continue
        next_hop = toks[2] if re.fullmatch(IP_RE, toks[2]) else ""
        proto = next((t.upper() for t in toks if t.upper() in ROUTE_PROTOCOLS), "")
        routes.append(Route(prefix=prefix, next_hop=next_hop, protocol=proto, vrf=vrf))
    return routes


def parse_ip_arp(text: str) -> list[ArpEntry]:
    out = []
    for line in text.splitlines():
        m = re.match(rf"\s*({IP_RE})\s+({MAC_RE})\s+(.*)$", line)
        if not m:
            continue
        pm = re.search(rf"\b({PORT_RE}|Mlt\d+|Cpp)\b", m.group(3))
        out.append(ArpEntry(ip=m.group(1), mac=norm_mac(m.group(2)),
                            port=pm.group(1) if pm else ""))
    return out


def parse_fdb(text: str) -> list[FdbEntry]:
    out = []
    for line in text.splitlines():
        toks = line.split()
        if not toks or not toks[0].isdigit():
            continue
        mac = next((t for t in toks if re.fullmatch(MAC_RE, t)), "")
        if not mac:
            continue
        status = next((t.lower() for t in toks if t.lower() in ("learned", "self", "static", "moving")), "")
        if status == "self":
            continue  # the switch's own MAC, not a neighbor
        pm = re.search(rf"(?:Port-)?({PORT_RE}|Mlt\d+)", line)
        if not pm:
            continue
        out.append(FdbEntry(vlan=toks[0], mac=norm_mac(mac), port=pm.group(1)))
    return out


class ExtremeVossPlugin(VendorPlugin):
    name = "extreme_voss"
    vendor = "Extreme Networks"
    netmiko_device_type = "extreme_vsp"
    match_keywords = ("voss", "vsp-", "vsp ", "fabric engine", "fabricengine")

    def get_identity(self, device: Device, ctx: CollectContext) -> None:
        info = parse_sys_info(ctx.ssh.send("show sys-info"))
        device.hostname = info.get("hostname", device.hostname)
        device.model = info.get("model", device.model)
        device.serial = info.get("serial", device.serial)
        device.sw_version = info.get("sw_version", device.sw_version)
        device.sys_descr = info.get("sys_descr", device.sys_descr)

    def get_interfaces(self, device: Device, ctx: CollectContext) -> None:
        device.interfaces = parse_interfaces(
            ctx.ssh.send("show interfaces gigabitEthernet interface", timeout=60))

    def get_lldp(self, device: Device, ctx: CollectContext) -> None:
        device.neighbors += parse_lldp_neighbor(ctx.ssh.send("show lldp neighbor", timeout=60))
        # Fabric context: not fatal if this box runs no SPBM / vIST.
        for cmd, parser in (("show isis adjacencies", parse_isis_adjacencies),
                            ("show virtual-ist", parse_virtual_ist)):
            try:
                device.neighbors += parser(ctx.ssh.send(cmd))
            except Exception as exc:
                device.errors.append(f"{cmd}: {exc}")

    def get_fdb(self, device: Device, ctx: CollectContext) -> None:
        device.fdb = parse_fdb(ctx.ssh.send("show vlan mac-address-entry", timeout=90))

    def get_routes(self, device: Device, ctx: CollectContext) -> None:
        device.routes = parse_ip_route(ctx.ssh.send("show ip route", timeout=60))

    def get_arp(self, device: Device, ctx: CollectContext) -> None:
        device.arp = parse_ip_arp(ctx.ssh.send("show ip arp", timeout=60))

    def classify(self, device: Device) -> str:
        return "switch"
