# NetMapper — Design Paper

*Network topology discovery, visualization, and troubleshooting — built VOSS-first.*

**Status:** awaiting go-ahead before implementation. Nothing below is coded yet.

---

## 1. What it is

NetMapper is a **read-only** Python CLI tool. You give it one or more seed devices
(management IPs) and a credential profile. It logs in, asks each device who its
neighbors are (LLDP first, then FDB, routing table, ARP, ICMP as decreasing-trust
sources), and recursively walks outward up to a configurable depth. The result is a
topology graph that can be viewed in the terminal, opened as an interactive HTML
page, analyzed for problems, and exported.

**Primary platform: Extreme VSP/VOSS.** Everything else (Extreme Universal/EXOS,
Juniper, FortiGate, Check Point, generic fallback) is supported but thinner.

## 2. Guiding constraints (agreed with you)

| Decision | Choice |
|---|---|
| Complexity budget | A working tool, **not** enterprise software. No servers, no databases, no async framework. |
| Python | 3.11+ |
| External libraries | **Three**: `netmiko`, `pysnmp`, `networkx`. Everything else is stdlib. |
| SSH | Netmiko only (revised from the earlier Scrapli+Netmiko choice — one library covers all five vendors with existing tested drivers, incl. `extreme_vsp`) |
| SNMP | v2c + v3 (v3 preferred when configured) |
| Concurrency | `concurrent.futures.ThreadPoolExecutor`, bounded worker count, BFS in depth waves |
| Storage | JSON snapshot files per run — no database |
| Credentials | Username from config/env, **password via `getpass` prompt** (or env var for unattended runs). Never written to disk. |
| Visualization | Single self-contained HTML file, embedded **vanilla JS + SVG**, no CDN/no external JS libs (corporate browser-safe) |
| CLI | stdlib `argparse` |
| Models | stdlib `dataclasses` |
| Config | TOML via stdlib `tomllib` |

## 3. How discovery works

```
seeds ──> queue(depth 0)
            │  ThreadPoolExecutor (default 10 workers)
            ▼
   ┌─ per device ────────────────────────────────┐
   │ 1. fingerprint (SNMP sysObjectID/sysDescr,  │
   │    else SSH banner) → pick vendor plugin    │
   │ 2. collect (read-only commands only):       │
   │      identity, interfaces, LLDP, FDB,       │
   │      routes, ARP                            │
   │ 3. emit neighbor candidates with source +   │
   │    confidence (LLDP 1.0 · FDB 0.7 ·         │
   │    routes 0.5 · ARP 0.4 · ICMP 0.2)         │
   └─────────────────────────────────────────────┘
            │ new mgmt IPs, deduped
            ▼
        queue(depth+1)   … until max-depth or nothing new
```

- Devices we can ping but not log into still become graph nodes (classified
  `unknown`/`endpoint`), they just don't expand further.
- Failures are recorded per device (auth failed / unreachable / timeout) and
  become analysis findings, not crashes.
- Read-only is enforced centrally: the driver base class only sends commands
  matching an allowlist (`show …`, `display …`, etc.).

## 4. Vendor plugins

A plugin is one class implementing a small interface:

```python
class VendorPlugin:
    def get_identity(...)     # hostname, vendor, model, sw version
    def get_interfaces(...)
    def get_lldp_neighbors(...)
    def get_fdb(...)
    def get_routes(...)
    def get_arp(...)
    def classify(...)         # switch/router/firewall/server/endpoint/iot/unknown
```

Registered in a plain dict; selected by fingerprint. Parsing is regex-based per
plugin (no TextFSM dependency — VOSS output is regular enough).

| Plugin | Depth of support |
|---|---|
| **extreme_voss** | Flagship. `show lldp neighbor`, `show interfaces gigabitEthernet name`, `show ip route [vrf]`, `show ip arp`, `show mac-address-table`, `show sys-info`, plus VOSS-specific context: `show isis adjacencies` (SPBM fabric links) and `show virtual-ist` — vIST/SMLT pairs are tagged on edges so analysis doesn't flag them as anomalies. |
| extreme_universal | LLDP, identity, interfaces, routes (EXOS/Universal syntax) |
| juniper_junos | LLDP, identity, interfaces, routes |
| fortigate | LLDP, identity, interfaces, routes, ARP |
| checkpoint_gaia | identity, interfaces, routes, ARP |
| generic | SNMP standard MIBs (LLDP-MIB, Q-BRIDGE-MIB, IP-FORWARD-MIB, IP-MIB) + ICMP; used when nothing else matches |

## 5. Data model (dataclasses → JSON)

- **Device**: hostname, mgmt IP, vendor, model, sw version, device type,
  interfaces, routes, discovery status, depth
- **Edge**: device A/interface A ↔ device B/interface B, discovery source,
  confidence, tags (e.g. `vist`, `smlt`, `spbm`)
- **Finding**: rule id, severity (`critical/warning/info`), affected objects,
  evidence (the actual data that triggered it), recommendation
- **Snapshot**: one run = one timestamped directory:
  `runs/2026-07-06T14-30-00/ {run.json, devices.json, edges.json, findings.json}`
  with a `schema_version` field for future-proofing.

The graph itself is a `networkx.Graph` built from devices+edges at load time.

## 6. Analysis rules

Each rule is a small function over the graph + snapshot; all produce
severity/evidence/recommendation:

1. Unreachable / login-failed devices
2. Asymmetric LLDP (A sees B, B doesn't see A)
3. Isolated segments (disconnected graph components)
4. Single points of failure (articulation points & bridge links — skipping
   known vIST pairs)
5. Duplicate management IPs / duplicate hostnames
6. Routing anomalies (no default route where peers have one; same prefix with
   conflicting next-hops)
7. Interface issues (admin-up/oper-down on links that carry LLDP neighbors,
   error counters where available)
8. Topology changes — diff against a previous run: appeared/vanished devices
   and links, changed software versions

## 7. Visualization & export

1. **Interactive HTML** (`netmapper viz`): one self-contained file. Embedded
   vanilla JS renders the graph as SVG: force-ish layout precomputed in Python
   (so the JS stays dumb), pan/zoom/drag, click a node for its detail panel,
   edges colored by confidence, findings shown as badges. Works from `file://`,
   offline, no CDN — immune to corporate browser lockdown.
2. **Terminal** (`netmapper show`): plain-text device table and per-device
   neighbor tree; findings table from `netmapper analyze`.
3. **Exports** (`netmapper export`): JSON (native), GraphML (yEd/Gephi, via
   networkx), DOT (Graphviz), Mermaid (paste into docs/wikis).

## 8. CLI

```
netmapper discover --seeds 10.0.0.1,10.0.0.2 --profile lab [--depth 3] [--workers 10]
netmapper show     [--run latest] [--device <name>]
netmapper analyze  [--run latest] [--compare-to <run>]
netmapper viz      [--run latest] [--open]
netmapper export   --format graphml|dot|mermaid|json [--out FILE]
netmapper runs     # list stored runs
```

Config file (`netmapper.toml`): auth profiles (username, SNMP community/v3
params, port overrides — no passwords), seed lists, defaults for depth/workers.

## 9. Project layout

```
netmapper/
├── pyproject.toml            # deps: netmiko, pysnmp, networkx
├── netmapper.toml.example
├── netmapper/
│   ├── cli.py                # argparse entry point
│   ├── config.py             # tomllib config + credential resolution (getpass/env)
│   ├── models.py             # dataclasses
│   ├── engine.py             # BFS discovery, thread pool, dedup, depth control
│   ├── transports.py         # netmiko wrapper (read-only guard), pysnmp helper, ping
│   ├── fingerprint.py        # plugin selection
│   ├── plugins/              # base.py, extreme_voss.py, extreme_universal.py,
│   │                         # juniper.py, fortigate.py, checkpoint.py, generic.py
│   ├── topology.py           # graph build, layout precompute, snapshot diff
│   ├── analysis.py           # the 8 rules
│   ├── store.py              # JSON run storage
│   ├── viz_html.py           # HTML template + data injection
│   ├── viz_term.py           # terminal output
│   └── export.py             # graphml/dot/mermaid
└── tests/                    # pytest, fixtures = recorded CLI outputs (VOSS-heavy)
```

Rough size estimate: ~3,000–3,500 lines of Python plus the ~300-line embedded JS
template. Small enough to read in an afternoon.

## 10. Implementation order

1. Skeleton: models, config, store, CLI wiring
2. Transports + read-only guard + fingerprinting
3. **extreme_voss plugin** + generic plugin → end-to-end discovery works
4. Topology graph + terminal view + JSON/graphml/dot/mermaid export
5. HTML visualization
6. Analysis rules + run diffing
7. Remaining vendor plugins (universal, juniper, fortigate, checkpoint)
8. Tests against recorded device outputs

## 11. Explicitly out of scope (anti-overengineering)

No web server, no database, no async framework, no plugin entry-points system,
no scheduler/daemon mode, no config-push of any kind (read-only forever), no
JavaScript build tooling, no Docker requirement. Any of these can be bolted on
later without restructuring.
