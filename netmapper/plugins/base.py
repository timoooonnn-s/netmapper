"""Plugin contract: collect device facts over an SSH session and/or SNMP."""
from __future__ import annotations

from dataclasses import dataclass

from ..config import SnmpSettings
from ..models import Device


@dataclass
class CollectContext:
    ssh: object | None = None          # transports.SSHSession, already opened
    snmp_host: str = ""
    snmp: SnmpSettings | None = None


class VendorPlugin:
    name = "base"
    vendor = ""
    netmiko_device_type = ""           # empty means no SSH CLI support
    match_keywords: tuple[str, ...] = ()

    @classmethod
    def matches(cls, text: str) -> bool:
        t = (text or "").lower()
        return any(k in t for k in cls.match_keywords)

    def collect(self, device: Device, ctx: CollectContext) -> None:
        """Run all collectors; one failing step must not kill the rest."""
        from ..transports import ReadOnlyViolation
        steps = (
            ("identity", self.get_identity),
            ("interfaces", self.get_interfaces),
            ("lldp", self.get_lldp),
            ("fdb", self.get_fdb),
            ("routes", self.get_routes),
            ("arp", self.get_arp),
        )
        for label, step in steps:
            try:
                step(device, ctx)
            except ReadOnlyViolation:
                raise  # a plugin bug - never swallow this
            except Exception as exc:
                device.errors.append(f"{label}: {exc}")
        device.plugin = self.name
        if self.vendor and not device.vendor:
            device.vendor = self.vendor
        device.device_type = self.classify(device)

    # Collectors - override what the platform supports.
    def get_identity(self, device: Device, ctx: CollectContext) -> None: ...
    def get_interfaces(self, device: Device, ctx: CollectContext) -> None: ...
    def get_lldp(self, device: Device, ctx: CollectContext) -> None: ...
    def get_fdb(self, device: Device, ctx: CollectContext) -> None: ...
    def get_routes(self, device: Device, ctx: CollectContext) -> None: ...
    def get_arp(self, device: Device, ctx: CollectContext) -> None: ...

    def classify(self, device: Device) -> str:
        text = f"{device.sys_descr} {device.model}".lower()
        if any(w in text for w in ("fortigate", "check point", "checkpoint", "firewall", "srx")):
            return "firewall"
        if device.fdb or "switch" in text:
            return "switch"
        if any(r.protocol.lower() in ("ospf", "bgp", "isis", "rip") for r in device.routes):
            return "router"
        if device.routes:
            return "router"
        return device.device_type or "unknown"
