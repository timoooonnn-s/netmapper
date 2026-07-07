"""Data model: plain dataclasses, JSON-serializable with to_dict()/from_dict helpers."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

SCHEMA_VERSION = 1

# Trust placed in each discovery source when it claims a relationship.
CONFIDENCE = {
    "lldp": 1.0,
    "isis": 0.95,  # SPBM fabric adjacency (VOSS)
    "vist": 0.9,   # virtual IST peer (VOSS)
    "fdb": 0.7,
    "route": 0.5,
    "arp": 0.4,
    "icmp": 0.2,
}

DEVICE_TYPES = ("switch", "router", "firewall", "server", "endpoint", "iot", "unknown")


def norm_mac(raw: str) -> str:
    """Normalize any MAC notation (aa:bb.., aabb.ccdd.., AA-BB-..) to aa:bb:cc:dd:ee:ff."""
    hexs = re.sub(r"[^0-9a-fA-F]", "", raw or "").lower()
    if len(hexs) != 12:
        return ""
    return ":".join(hexs[i:i + 2] for i in range(0, 12, 2))


def norm_hostname(raw: str) -> str:
    """Lowercased short hostname (domain suffix stripped) for cross-device matching."""
    return (raw or "").strip().strip('"').split(".")[0].lower()


@dataclass
class Interface:
    name: str
    description: str = ""
    admin_status: str = ""
    oper_status: str = ""
    mac: str = ""
    ips: list[str] = field(default_factory=list)


@dataclass
class Route:
    prefix: str
    next_hop: str = ""
    protocol: str = ""
    interface: str = ""
    vrf: str = "GlobalRouter"


@dataclass
class ArpEntry:
    ip: str
    mac: str
    port: str = ""


@dataclass
class FdbEntry:
    vlan: str
    mac: str
    port: str


@dataclass
class NeighborCandidate:
    """One claim, by one device, that something is attached to it."""

    local_interface: str = ""
    remote_hostname: str = ""
    remote_ip: str = ""
    remote_mac: str = ""
    remote_interface: str = ""
    remote_descr: str = ""
    source: str = "lldp"
    tags: list[str] = field(default_factory=list)

    @property
    def confidence(self) -> float:
        return CONFIDENCE.get(self.source, 0.1)


@dataclass
class Device:
    mgmt_ip: str
    hostname: str = ""
    vendor: str = ""
    model: str = ""
    serial: str = ""
    sw_version: str = ""
    device_type: str = "unknown"
    plugin: str = ""
    # ok | ping_only | stub | unreachable | auth_failed | error
    status: str = "pending"
    depth: int = 0
    rtt_ms: float | None = None
    sys_descr: str = ""
    aliases: list[str] = field(default_factory=list)  # extra mgmt IPs merged into this node
    interfaces: list[Interface] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    arp: list[ArpEntry] = field(default_factory=list)
    fdb: list[FdbEntry] = field(default_factory=list)
    neighbors: list[NeighborCandidate] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def node_id(self) -> str:
        return self.mgmt_ip or f"name:{norm_hostname(self.hostname) or 'unknown'}"

    @property
    def label(self) -> str:
        return self.hostname or self.mgmt_ip or "?"


@dataclass
class Edge:
    a: str      # node_id
    a_if: str
    b: str      # node_id
    b_if: str
    source: str          # highest-confidence source that produced this edge
    confidence: float
    sources: list[str] = field(default_factory=list)
    reported_by: list[str] = field(default_factory=list)  # node_ids that claimed it
    tags: list[str] = field(default_factory=list)

    def pair(self) -> frozenset:
        return frozenset((self.a, self.b))


@dataclass
class Finding:
    rule: str
    severity: str        # critical | warning | info
    title: str
    affected: list[str] = field(default_factory=list)
    evidence: str = ""
    recommendation: str = ""


@dataclass
class RunMeta:
    run_id: str
    started: str
    finished: str = ""
    profile: str = ""
    seeds: list[str] = field(default_factory=list)
    max_depth: int = 0
    stats: dict[str, Any] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION


def to_dict(obj) -> dict:
    return asdict(obj)


def _fields_only(cls, d: dict) -> dict:
    return {k: v for k, v in d.items() if k in cls.__dataclass_fields__}


def device_from_dict(d: dict) -> Device:
    dev = Device(mgmt_ip=d.get("mgmt_ip", ""))
    nested = {
        "interfaces": Interface, "routes": Route, "arp": ArpEntry,
        "fdb": FdbEntry, "neighbors": NeighborCandidate,
    }
    for k, v in d.items():
        if k in nested:
            setattr(dev, k, [nested[k](**_fields_only(nested[k], i)) for i in v])
        elif k in Device.__dataclass_fields__:
            setattr(dev, k, v)
    return dev


def edge_from_dict(d: dict) -> Edge:
    return Edge(**_fields_only(Edge, d))


def finding_from_dict(d: dict) -> Finding:
    return Finding(**_fields_only(Finding, d))


def runmeta_from_dict(d: dict) -> RunMeta:
    return RunMeta(**_fields_only(RunMeta, d))
