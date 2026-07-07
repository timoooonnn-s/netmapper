"""Pick the vendor plugin for a device from its SNMP sysDescr or a netmiko
autodetect guess. Order matters: VOSS is checked first (primary platform)."""
from __future__ import annotations

from .plugins.base import VendorPlugin
from .plugins.checkpoint import CheckpointPlugin
from .plugins.extreme_universal import ExtremeUniversalPlugin
from .plugins.extreme_voss import ExtremeVossPlugin
from .plugins.fortigate import FortigatePlugin
from .plugins.generic import GenericPlugin
from .plugins.juniper import JuniperPlugin

ORDERED: list[type[VendorPlugin]] = [
    ExtremeVossPlugin,
    ExtremeUniversalPlugin,
    JuniperPlugin,
    FortigatePlugin,
    CheckpointPlugin,
]

NETMIKO_MAP: dict[str, type[VendorPlugin]] = {
    "extreme_vsp": ExtremeVossPlugin,
    "extreme_exos": ExtremeUniversalPlugin,
    "extreme": ExtremeUniversalPlugin,
    "juniper_junos": JuniperPlugin,
    "juniper": JuniperPlugin,
    "fortinet": FortigatePlugin,
    "checkpoint_gaia": CheckpointPlugin,
}


def select_plugin(text: str) -> type[VendorPlugin]:
    for cls in ORDERED:
        if text and cls.matches(text):
            return cls
    return GenericPlugin


def plugin_for_netmiko(device_type: str | None) -> type[VendorPlugin] | None:
    if not device_type:
        return None
    return NETMIKO_MAP.get(device_type)
