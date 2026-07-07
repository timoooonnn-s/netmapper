import pytest

from netmapper.transports import ReadOnlyViolation, ensure_read_only


@pytest.mark.parametrize("cmd", [
    "show sys-info", "show ip route vrf blue", "display version",
    "get system status", "get router info routing-table all",
    "diagnose lldprx neighbor", "show lldp neighbor", "cpstat os",
    "fw stat", "traceroute 10.0.0.1",
])
def test_read_commands_pass(cmd):
    ensure_read_only(cmd)


@pytest.mark.parametrize("cmd", [
    "configure terminal", "config system interface", "reboot", "reset",
    "no shutdown", "write memory", "copy running-config startup-config",
    "delete vlan 10", "set snmp community rw", "boot config", "clear logging",
    "shutdown", "save config", "getconfig",  # 'getconfig' != 'get '
    "", "  ",
])
def test_write_commands_blocked(cmd):
    with pytest.raises(ReadOnlyViolation):
        ensure_read_only(cmd)
