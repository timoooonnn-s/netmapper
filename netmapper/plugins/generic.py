"""Generic fallback plugin: standard SNMP MIBs only (no SSH CLI).

Used for anything that no vendor plugin matches. Pulls identity from
SNMPv2-MIB, neighbors from LLDP-MIB, ARP from IP-MIB and routes from
IP-FORWARD-MIB. Without working SNMP the device stays a ping-only node.
"""
from __future__ import annotations

import re

from ..models import ArpEntry, Device, NeighborCandidate, Route
from .base import CollectContext, VendorPlugin

OID_SYSDESCR = "1.3.6.1.2.1.1.1.0"
OID_SYSOBJECTID = "1.3.6.1.2.1.1.2.0"
OID_SYSNAME = "1.3.6.1.2.1.1.5.0"

LLDP_LOC_PORT_DESC = "1.0.8802.1.1.2.1.3.7.1.4"
LLDP_REM_CHASSIS = "1.0.8802.1.1.2.1.4.1.1.5"
LLDP_REM_PORTID = "1.0.8802.1.1.2.1.4.1.1.7"
LLDP_REM_SYSNAME = "1.0.8802.1.1.2.1.4.1.1.9"
LLDP_REM_SYSDESC = "1.0.8802.1.1.2.1.4.1.1.10"

ARP_PHYS = "1.3.6.1.2.1.4.22.1.2"           # ipNetToMediaPhysAddress (index ifIndex.ip)
ROUTE_PROTO = "1.3.6.1.2.1.4.24.4.1.7"      # ipCidrRouteProto (index dst.mask.tos.nh)

ROUTE_PROTO_NAMES = {2: "local", 3: "static", 8: "rip", 9: "isis", 13: "ospf", 14: "bgp"}

MAC_LIKE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


def _suffix(oid: str, base: str) -> list[str]:
    return oid[len(base) + 1:].split(".") if oid.startswith(base + ".") else []


class GenericPlugin(VendorPlugin):
    name = "generic"
    vendor = ""
    netmiko_device_type = ""   # SNMP / ICMP only
    match_keywords = ()

    def collect(self, device: Device, ctx: CollectContext) -> None:
        if not (ctx.snmp and ctx.snmp.usable):
            device.errors.append("generic: no usable SNMP settings; node stays ICMP-only")
            device.plugin = self.name
            return
        from .. import transports as t
        host, s = ctx.snmp_host or device.mgmt_ip, ctx.snmp

        vals = t.snmp_get(host, s, [OID_SYSDESCR, OID_SYSNAME])
        device.sys_descr = vals.get(OID_SYSDESCR, device.sys_descr)
        if vals.get(OID_SYSNAME):
            device.hostname = vals[OID_SYSNAME]

        self._lldp(device, t, host, s)
        self._arp(device, t, host, s)
        self._routes(device, t, host, s)

        device.plugin = self.name
        device.device_type = self.classify(device)

    def _lldp(self, device: Device, t, host: str, s) -> None:
        port_names = {}
        for oid, val in t.snmp_walk(host, s, LLDP_LOC_PORT_DESC):
            sfx = _suffix(oid, LLDP_LOC_PORT_DESC)
            if sfx:
                port_names[sfx[0]] = val
        rem: dict[tuple[str, str], NeighborCandidate] = {}

        def entry(oid: str, base: str) -> NeighborCandidate | None:
            sfx = _suffix(oid, base)
            if len(sfx) != 3:
                return None
            key = (sfx[1], sfx[2])  # (localPortNum, remIndex)
            if key not in rem:
                rem[key] = NeighborCandidate(
                    local_interface=port_names.get(sfx[1], f"port{sfx[1]}"), source="lldp")
            return rem[key]

        for base, attr in ((LLDP_REM_SYSNAME, "remote_hostname"),
                           (LLDP_REM_PORTID, "remote_interface"),
                           (LLDP_REM_SYSDESC, "remote_descr"),
                           (LLDP_REM_CHASSIS, "remote_mac")):
            for oid, val in t.snmp_walk(host, s, base):
                c = entry(oid, base)
                if c is None:
                    continue
                if attr == "remote_mac":
                    val = val if MAC_LIKE.match(val) else ""
                if val:
                    setattr(c, attr, val)
        device.neighbors += [c for c in rem.values() if c.remote_hostname or c.remote_mac]

    def _arp(self, device: Device, t, host: str, s) -> None:
        for oid, val in t.snmp_walk(host, s, ARP_PHYS):
            sfx = _suffix(oid, ARP_PHYS)
            if len(sfx) == 5 and MAC_LIKE.match(val):
                device.arp.append(ArpEntry(ip=".".join(sfx[1:5]), mac=val))

    def _routes(self, device: Device, t, host: str, s) -> None:
        for oid, val in t.snmp_walk(host, s, ROUTE_PROTO):
            sfx = _suffix(oid, ROUTE_PROTO)
            if len(sfx) != 13:
                continue
            dst, mask, nh = ".".join(sfx[0:4]), ".".join(sfx[4:8]), ".".join(sfx[9:13])
            import ipaddress
            try:
                prefix = str(ipaddress.ip_network(f"{dst}/{mask}", strict=False))
                proto = ROUTE_PROTO_NAMES.get(int(val), "")
            except ValueError:
                continue
            device.routes.append(Route(
                prefix=prefix, next_hop="" if nh == "0.0.0.0" else nh, protocol=proto))
