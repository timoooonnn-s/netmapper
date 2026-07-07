"""Topology: turn per-device neighbor claims into a deduplicated edge list,
build the networkx graph, compute a layout, diff two runs."""
from __future__ import annotations

import math
import random

import networkx as nx

from .models import CONFIDENCE, Device, Edge, NeighborCandidate, norm_hostname


# ---------------------------------------------------------------- edges

def build_edges(devices: dict[str, Device]) -> tuple[list[Edge], dict[str, Device]]:
    """Resolve every device's neighbor candidates against the discovered device
    set. Unresolvable targets become stub devices. Returns (edges, stubs)."""
    ip_index: dict[str, str] = {}
    name_index: dict[str, str] = {}
    mac_index: dict[str, str] = {}
    for nid, d in devices.items():
        for ip in [d.mgmt_ip, *d.aliases]:
            if ip:
                ip_index.setdefault(ip, nid)
        for i in d.interfaces:
            if i.mac:
                mac_index.setdefault(i.mac, nid)
            for ip in i.ips:
                ip_index.setdefault(ip.split("/")[0], nid)
        if d.hostname:
            name_index.setdefault(norm_hostname(d.hostname), nid)

    stubs: dict[str, Device] = {}
    raw: list[Edge] = []
    for nid, d in devices.items():
        for c in d.neighbors:
            target = _resolve(c, ip_index, name_index, mac_index)
            if target is None:
                target = _stub_for(c, stubs, ip_index)
            if target == nid:
                continue
            raw.append(Edge(
                a=nid, a_if=c.local_interface, b=target, b_if=c.remote_interface,
                source=c.source, confidence=c.confidence,
                sources=[c.source], reported_by=[nid], tags=list(c.tags),
            ))
    return _merge_edges(raw), stubs


def _resolve(c: NeighborCandidate, ip_index, name_index, mac_index) -> str | None:
    if c.remote_ip and c.remote_ip in ip_index:
        return ip_index[c.remote_ip]
    if c.remote_hostname and norm_hostname(c.remote_hostname) in name_index:
        return name_index[norm_hostname(c.remote_hostname)]
    if c.remote_mac and c.remote_mac in mac_index:
        return mac_index[c.remote_mac]
    return None


def _stub_for(c: NeighborCandidate, stubs: dict[str, Device], ip_index: dict) -> str:
    dev = Device(
        mgmt_ip=c.remote_ip, hostname=c.remote_hostname, status="stub",
        sys_descr=c.remote_descr,
        device_type="endpoint" if c.source in ("fdb", "arp") else "unknown",
    )
    if not (c.remote_ip or c.remote_hostname):
        dev.hostname = c.remote_mac  # last resort: label stub by MAC
    nid = dev.node_id
    if nid not in stubs:
        stubs[nid] = dev
        if dev.mgmt_ip:
            ip_index.setdefault(dev.mgmt_ip, nid)
    return nid


def _merge_edges(raw: list[Edge]) -> list[Edge]:
    """Merge duplicate reports of the same link (both directions, multiple
    sources). Parallel links with distinct interface pairs are kept apart."""
    by_pair: dict[frozenset, list[Edge]] = {}
    for e in sorted(raw, key=lambda e: -e.confidence):
        _orient(e)
        placed = False
        for r in by_pair.setdefault(e.pair(), []):
            if _compatible(r, e):
                r.a_if = r.a_if or e.a_if
                r.b_if = r.b_if or e.b_if
                r.sources = sorted(set(r.sources) | set(e.sources))
                r.reported_by = sorted(set(r.reported_by) | set(e.reported_by))
                r.tags = sorted(set(r.tags) | set(e.tags))
                r.confidence = max(r.confidence, e.confidence)
                placed = True
                break
        if not placed:
            by_pair[e.pair()].append(e)
    return [e for group in by_pair.values() for e in group]


def _orient(e: Edge) -> None:
    if e.b < e.a:
        e.a, e.b, e.a_if, e.b_if = e.b, e.a, e.b_if, e.a_if


def _compatible(r: Edge, e: Edge) -> bool:
    ok_a = not r.a_if or not e.a_if or r.a_if == e.a_if
    ok_b = not r.b_if or not e.b_if or r.b_if == e.b_if
    return ok_a and ok_b


# ---------------------------------------------------------------- graph

def build_graph(devices: dict[str, Device], edges: list[Edge]) -> nx.Graph:
    g = nx.Graph()
    for nid, d in devices.items():
        g.add_node(nid, label=d.label, device_type=d.device_type, status=d.status,
                   vendor=d.vendor, model=d.model, sw_version=d.sw_version, depth=d.depth)
    for e in edges:
        # Graph keeps one edge per node pair (highest confidence); the full
        # parallel-link detail lives in the edge list.
        if g.has_edge(e.a, e.b) and g.edges[e.a, e.b].get("confidence", 0) >= e.confidence:
            continue
        g.add_edge(e.a, e.b, source=e.source, confidence=e.confidence, tags=",".join(e.tags))
    return g


# ---------------------------------------------------------------- layout

def layout(devices: dict[str, Device], edges: list[Edge],
           width: int = 1600, height: int = 1000, iterations: int = 250,
           seed: int = 42) -> dict[str, tuple[float, float]]:
    """Pure-python Fruchterman-Reingold force layout (no numpy needed).
    Fine for the 10-300 node graphs this tool targets."""
    nodes = list(devices)
    n = len(nodes)
    if n == 0:
        return {}
    if n == 1:
        return {nodes[0]: (width / 2, height / 2)}
    rnd = random.Random(seed)
    pos = {v: [rnd.uniform(0, width), rnd.uniform(0, height)] for v in nodes}
    pairs = {(e.a, e.b) for e in edges if e.a in pos and e.b in pos}
    k = math.sqrt(width * height / n) * 0.7
    t = width / 8
    dt = t / (iterations + 1)
    for _ in range(iterations):
        disp = {v: [0.0, 0.0] for v in nodes}
        for i, v in enumerate(nodes):          # repulsion, O(n^2)
            for u in nodes[i + 1:]:
                dx = pos[v][0] - pos[u][0]
                dy = pos[v][1] - pos[u][1]
                d2 = dx * dx + dy * dy or 0.01
                f = k * k / d2
                disp[v][0] += dx * f
                disp[v][1] += dy * f
                disp[u][0] -= dx * f
                disp[u][1] -= dy * f
        for a, b in pairs:                     # attraction along edges
            dx = pos[a][0] - pos[b][0]
            dy = pos[a][1] - pos[b][1]
            d = math.sqrt(dx * dx + dy * dy) or 0.1
            f = d / k
            disp[a][0] -= dx / d * d * f
            disp[a][1] -= dy / d * d * f
            disp[b][0] += dx / d * d * f
            disp[b][1] += dy / d * d * f
        for v in nodes:
            dx, dy = disp[v]
            d = math.sqrt(dx * dx + dy * dy) or 0.1
            pos[v][0] += dx / d * min(d, t)
            pos[v][1] += dy / d * min(d, t)
            pos[v][0] = min(width - 40, max(40, pos[v][0]))
            pos[v][1] = min(height - 40, max(40, pos[v][1]))
        t -= dt
    return {v: (round(p[0], 1), round(p[1], 1)) for v, p in pos.items()}


# ---------------------------------------------------------------- diff

def diff_runs(old_devices: dict[str, Device], old_edges: list[Edge],
              new_devices: dict[str, Device], new_edges: list[Edge]) -> dict:
    def edge_key(e: Edge):
        return tuple(sorted([(e.a, e.a_if), (e.b, e.b_if)]))

    old_e = {edge_key(e): e for e in old_edges}
    new_e = {edge_key(e): e for e in new_edges}
    out = {
        "added_devices": sorted(set(new_devices) - set(old_devices)),
        "removed_devices": sorted(set(old_devices) - set(new_devices)),
        "added_edges": [new_e[k] for k in new_e.keys() - old_e.keys()],
        "removed_edges": [old_e[k] for k in old_e.keys() - new_e.keys()],
        "version_changes": [],
        "status_changes": [],
    }
    for nid in set(old_devices) & set(new_devices):
        o, n = old_devices[nid], new_devices[nid]
        if o.sw_version and n.sw_version and o.sw_version != n.sw_version:
            out["version_changes"].append((nid, o.sw_version, n.sw_version))
        if o.status != n.status:
            out["status_changes"].append((nid, o.status, n.status))
    return out
