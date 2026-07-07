# NetMapper

Read-only network topology discovery, visualization and troubleshooting,
built **Extreme VOSS/VSP first** (SPBM fabric, vIST/SMLT aware), with support
for Extreme Switch Engine (EXOS), Juniper, FortiGate, Check Point and a
generic SNMP fallback for everything else.

You give it seed devices; it logs in read-only and walks the network using
authoritative relationships - **LLDP → FDB → routes → ARP → ICMP** - and
produces a topology graph, an analysis report and an interactive map.

Design rationale and architecture: see [DESIGN.md](DESIGN.md).

## Install

Python 3.11+.

```
pip install .
```

Three dependencies: `netmiko` (SSH), `pysnmp` (SNMP v2c/v3), `networkx` (graph).

## Quick start

```
cp netmapper.toml.example netmapper.toml     # edit profiles + seeds
export NETMAPPER_LAB_PASSWORD=...            # or let getpass prompt you

netmapper discover --seeds 10.0.0.1,10.0.0.2 --profile lab --depth 3
netmapper analyze                            # findings with severity/evidence/fix
netmapper viz --open                         # interactive HTML map (offline, no CDN)
netmapper show --tree                        # terminal neighbor tree
netmapper show --device core-vsp-1           # one device in detail
netmapper export -f graphml -o topo.graphml  # also: dot, mermaid, json
netmapper runs                               # list stored snapshots
```

Every discovery run is a timestamped JSON snapshot under `runs/`;
`netmapper analyze` automatically diffs against the previous run and reports
topology changes.

## Safety

The tool is strictly read-only: every CLI command a plugin sends passes a
central allowlist (`show`, `display`, `get`, ...) and anything else is
refused before it reaches the wire. SNMP is only ever GET/WALK.

## Notes

- CLI parsers are regex-based against common firmware output; minor column
  differences between releases are tolerated, but if a parser misses data on
  your firmware, the fixtures in `tests/fixtures/` show the expected shapes -
  adjust there first.
- Devices that answer ping but offer no SSH/SNMP become `ping_only` nodes;
  neighbors referenced but never reached become `stub` nodes, and both are
  called out by the analysis rules.
