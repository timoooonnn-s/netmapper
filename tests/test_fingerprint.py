from netmapper.fingerprint import plugin_for_netmiko, select_plugin
from netmapper.plugins.checkpoint import CheckpointPlugin
from netmapper.plugins.extreme_universal import ExtremeUniversalPlugin
from netmapper.plugins.extreme_voss import ExtremeVossPlugin
from netmapper.plugins.fortigate import FortigatePlugin
from netmapper.plugins.generic import GenericPlugin
from netmapper.plugins.juniper import JuniperPlugin


def test_sysdescr_fingerprints():
    cases = {
        "VSP-8284XSQ (8.10.1.0) BoxType: VSP-8284XSQ": ExtremeVossPlugin,
        "VOSS 8.2 on VSP-4850": ExtremeVossPlugin,
        "5520-48W Fabric Engine 9.0.2.0": ExtremeVossPlugin,
        "ExtremeXOS (X465-48T) version 31.7.1.4": ExtremeUniversalPlugin,
        "Juniper Networks, Inc. ex4300-48t Ethernet Switch, kernel JUNOS 21.4R3": JuniperPlugin,
        "FortiGate-100F v7.2.5": FortigatePlugin,
        "Linux cp-gw-1 3.10.0 Check Point Gaia R81.20": CheckpointPlugin,
        "Cisco IOS Software, C2960X": GenericPlugin,
        "": GenericPlugin,
    }
    for text, expected in cases.items():
        assert select_plugin(text) is expected, text


def test_netmiko_map():
    assert plugin_for_netmiko("extreme_vsp") is ExtremeVossPlugin
    assert plugin_for_netmiko("extreme_exos") is ExtremeUniversalPlugin
    assert plugin_for_netmiko("cisco_ios") is None
    assert plugin_for_netmiko(None) is None
