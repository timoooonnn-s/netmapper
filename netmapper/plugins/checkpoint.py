"""Check Point Gaia plugin (clish, read-only)."""
from __future__ import annotations

import re

from ..models import Device, Interface, Route, norm_mac, ArpEntry
from .base import CollectContext, VendorPlugin

MAC_RE = r"[0-9a-fA-F]{2}(?:[:.-][0-9a-fA-F]{2}){5}"
IP_RE = r"\d+\.\d+\.\d+\.\d+"

PROTO_LETTERS = {"S": "static", "C": "connected", "O": "ospf", "B": "bgp", "R": "rip", "K": "kernel"}


def parse_version(text: str) -> str:
    m = re.search(r"(R\d+(?:\.\d+)*)", text)
    return m.group(1) if m else ""


def parse_interfaces_all(text: str) -> list[Interface]:
    ifaces = []
    for name, body in zip(*(iter(re.split(r"(?mi)^Interface (\S+)", text)[1:]),) * 2):
        iface = Interface(name=name)
        m = re.search(rf"ipv4-address\s+({IP_RE}/?\d*)", body)
        if m and not m.group(1).startswith("0.0.0.0"):
            iface.ips.append(m.group(1))
        m = re.search(rf"mac-addr\s+({MAC_RE})", body)
        if m:
            iface.mac = norm_mac(m.group(1))
        m = re.search(r"state\s+(on|off)", body)
        if m:
            iface.admin_status = "up" if m.group(1) == "on" else "down"
        m = re.search(r"link-state\s+link\s+(up|down)", body)
        if m:
            iface.oper_status = m.group(1)
        ifaces.append(iface)
    return ifaces


def parse_route(text: str) -> list[Route]:
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


def parse_arp(text: str) -> list[ArpEntry]:
    out = []
    for line in text.splitlines():
        m = re.search(rf"({IP_RE}).*?({MAC_RE})", line)
        if m:
            out.append(ArpEntry(ip=m.group(1), mac=norm_mac(m.group(2))))
    return out


class CheckpointPlugin(VendorPlugin):
    name = "checkpoint_gaia"
    vendor = "Check Point"
    netmiko_device_type = "checkpoint_gaia"
    match_keywords = ("check point", "checkpoint", "gaia")

    def get_identity(self, device: Device, ctx: CollectContext) -> None:
        hostname = ctx.ssh.send("show hostname").strip().splitlines()
        if hostname:
            device.hostname = hostname[-1].strip()
        device.sw_version = parse_version(ctx.ssh.send("show version product"))
        device.model = device.model or "Check Point Gaia"

    def get_interfaces(self, device: Device, ctx: CollectContext) -> None:
        device.interfaces = parse_interfaces_all(
            ctx.ssh.send("show interfaces all", timeout=60))

    def get_routes(self, device: Device, ctx: CollectContext) -> None:
        device.routes = parse_route(ctx.ssh.send("show route", timeout=60))

    def get_arp(self, device: Device, ctx: CollectContext) -> None:
        device.arp = parse_arp(ctx.ssh.send("show arp dynamic all", timeout=60))

    def classify(self, device: Device) -> str:
        return "firewall"
