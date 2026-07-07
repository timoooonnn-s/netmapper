"""Analysis engine: rule functions over the topology. Every finding carries
severity, evidence and a recommendation."""
from __future__ import annotations

import networkx as nx

from .models import Device, Edge, Finding, norm_hostname
from .topology import build_graph, diff_runs

INFRA_TYPES = ("switch", "router", "firewall", "unknown")
SEV_ORDER = {"critical": 0, "warning": 1, "info": 2}


def analyze(devices: dict[str, Device], edges: list[Edge],
            prev: tuple[dict[str, Device], list[Edge]] | None = None) -> list[Finding]:
    g = build_graph(devices, edges)
    findings: list[Finding] = []
    findings += _unreachable(devices)
    findings += _missing_neighbors(devices, edges)
    findings += _asymmetric_lldp(devices, edges)
    findings += _isolated_segments(devices, g)
    findings += _spof(devices, g, edges)
    findings += _duplicates(devices)
    findings += _routing(devices)
    findings += _interfaces(devices, edges)
    if prev is not None:
        findings += _changes(devices, edges, prev)
    findings.sort(key=lambda f: (SEV_ORDER.get(f.severity, 9), f.rule))
    return findings


def _label(devices, nid: str) -> str:
    d = devices.get(nid)
    return f"{d.label} ({nid})" if d and d.label != nid else nid


def _unreachable(devices) -> list[Finding]:
    out = []
    for nid, d in devices.items():
        if d.status not in ("unreachable", "auth_failed", "error"):
            continue
        sev = "critical" if d.depth == 0 else "warning"
        why = {"unreachable": "no ICMP reply and no management access",
               "auth_failed": "reachable, but SSH authentication failed",
               "error": "probe crashed"}[d.status]
        out.append(Finding(
            rule="unreachable", severity=sev,
            title=f"{_label(devices, nid)}: {why}",
            affected=[nid],
            evidence=(f"status={d.status}, "
                      + (f"rtt={d.rtt_ms}ms" if d.rtt_ms is not None else "no ping reply")
                      + (f", errors={d.errors[:3]}" if d.errors else "")),
            recommendation=("Verify credentials in the auth profile" if d.status == "auth_failed"
                            else "Check device power/uplinks, mgmt ACLs and routing to the mgmt IP"),
        ))
    return out


def _missing_neighbors(devices, edges) -> list[Finding]:
    out = []
    for nid, d in devices.items():
        if d.status != "stub":
            continue
        claims = [e for e in edges if nid in (e.a, e.b)]
        srcs = {s for e in claims for s in e.sources}
        reporters = sorted({r for e in claims for r in e.reported_by})
        sev = "warning" if srcs & {"lldp", "isis"} else "info"
        out.append(Finding(
            rule="missing-neighbor", severity=sev,
            title=f"{_label(devices, nid)} referenced by neighbors but never discovered",
            affected=[nid] + reporters,
            evidence=f"claimed via {sorted(srcs)} by {[_label(devices, r) for r in reporters]}",
            recommendation="If this is infrastructure, add its mgmt IP as a seed or raise --depth; "
                           "if it is an endpoint, this is expected",
        ))
    return out


def _asymmetric_lldp(devices, edges) -> list[Finding]:
    out = []
    for e in edges:
        if "lldp" not in e.sources or len(set(e.reported_by)) != 1:
            continue
        reporter = e.reported_by[0]
        other = e.b if reporter == e.a else e.a
        od = devices.get(other)
        # Only a real asymmetry if the other side was collected and has LLDP data.
        if not od or od.status != "ok" or not any(c.source == "lldp" for c in od.neighbors):
            continue
        out.append(Finding(
            rule="asymmetric-lldp", severity="warning",
            title=f"one-way LLDP: {_label(devices, reporter)} sees {_label(devices, other)}, not vice versa",
            affected=[e.a, e.b],
            evidence=f"link {e.a_if or '?'} <-> {e.b_if or '?'} reported only by {_label(devices, reporter)}",
            recommendation="Check LLDP transmit/receive config on the far side, or an intermediate "
                           "device (unmanaged switch / hypervisor vSwitch) swallowing LLDP",
        ))
    return out


def _isolated_segments(devices, g: nx.Graph) -> list[Finding]:
    comps = sorted(nx.connected_components(g), key=len, reverse=True)
    out = []
    for comp in comps[1:]:
        members = sorted(comp)
        out.append(Finding(
            rule="isolated-segment", severity="warning",
            title=f"isolated segment with {len(members)} node(s), disconnected from the main topology",
            affected=members,
            evidence=f"members: {[_label(devices, m) for m in members[:10]]}",
            recommendation="Check whether a linking device is missing from discovery "
                           "(depth/credentials) or an uplink is actually down",
        ))
    return out


def _spof(devices, g: nx.Graph, edges) -> list[Finding]:
    infra = [n for n, d in devices.items()
             if d.status not in ("stub",) and d.device_type in INFRA_TYPES]
    sub = g.subgraph(infra)
    out = []
    if sub.number_of_nodes() >= 3:
        for ap in nx.articulation_points(sub):
            parts = [c for c in nx.connected_components(
                sub.subgraph([n for n in sub if n != ap]))]
            out.append(Finding(
                rule="single-point-of-failure", severity="warning",
                title=f"{_label(devices, ap)} is a single point of failure",
                affected=[ap],
                evidence=f"removing it splits the infrastructure into {len(parts)} island(s)",
                recommendation="Add a redundant path (second uplink, MLT/SMLT pair, ring) around this node",
            ))
        for a, b in nx.bridges(sub):
            e = next((x for x in edges if {x.a, x.b} == {a, b}), None)
            if e and {"vist", "smlt"} & set(e.tags):
                continue  # SMLT/vIST links have MLT redundancy behind them
            out.append(Finding(
                rule="single-point-of-failure", severity="info",
                title=f"link {_label(devices, a)} <-> {_label(devices, b)} is the only path between these parts",
                affected=[a, b],
                evidence=f"bridge edge ({(e.source if e else 'n/a')})",
                recommendation="Consider a second link or path between these devices",
            ))
    return out


def _duplicates(devices) -> list[Finding]:
    out = []
    by_name: dict[str, list[str]] = {}
    for nid, d in devices.items():
        if d.hostname and d.status != "stub":
            by_name.setdefault(norm_hostname(d.hostname), []).append(nid)
    for name, nids in by_name.items():
        if len(nids) > 1:
            out.append(Finding(
                rule="duplicate-identity", severity="warning",
                title=f"hostname '{name}' used by {len(nids)} devices",
                affected=nids, evidence=f"nodes: {nids}",
                recommendation="Rename one of them, or verify these are not the same box "
                               "reached over two IPs that failed alias-merge",
            ))
    by_ip: dict[str, list[str]] = {}
    for nid, d in devices.items():
        for i in d.interfaces:
            for ip in i.ips:
                by_ip.setdefault(ip.split("/")[0], []).append(nid)
    for ip, nids in by_ip.items():
        uniq = sorted(set(nids))
        if len(uniq) > 1:
            out.append(Finding(
                rule="duplicate-ip", severity="warning",
                title=f"IP {ip} configured on {len(uniq)} devices",
                affected=uniq,
                evidence=f"devices: {[_label(devices, n) for n in uniq]}",
                recommendation="Duplicate addressing - unless this is VRRP/anycast by design, fix it",
            ))
    return out


def _routing(devices) -> list[Finding]:
    routers = {nid: d for nid, d in devices.items() if d.routes}
    if len(routers) < 2:
        return []
    have_default = {nid for nid, d in routers.items()
                    if any(r.prefix == "0.0.0.0/0" for r in d.routes)}
    missing = set(routers) - have_default
    out = []
    if have_default and missing:
        out.append(Finding(
            rule="routing-anomaly", severity="info",
            title=f"{len(missing)} routing device(s) have no default route while "
                  f"{len(have_default)} do",
            affected=sorted(missing),
            evidence=f"without 0.0.0.0/0: {[_label(devices, n) for n in sorted(missing)]}",
            recommendation="Verify this is intentional (stub/isolated VRF) and not a missing route",
        ))
    return out


def _interfaces(devices, edges) -> list[Finding]:
    out = []
    for nid, d in devices.items():
        down = [i.name for i in d.interfaces
                if i.admin_status == "up" and i.oper_status == "down"]
        if down:
            out.append(Finding(
                rule="interface-issue", severity="info",
                title=f"{_label(devices, nid)}: {len(down)} interface(s) admin-up but oper-down",
                affected=[nid], evidence=f"ports: {down[:15]}",
                recommendation="Expected for unused ports; investigate any that should carry a link",
            ))
        oper = {i.name: i.oper_status for i in d.interfaces}
        for e in edges:
            if e.a == nid and oper.get(e.a_if) == "down" or e.b == nid and oper.get(e.b_if) == "down":
                port = e.a_if if e.a == nid else e.b_if
                out.append(Finding(
                    rule="interface-issue", severity="warning",
                    title=f"{_label(devices, nid)} port {port} carries a known link but is oper-down",
                    affected=[nid, e.b if e.a == nid else e.a],
                    evidence=f"edge {e.a}:{e.a_if} <-> {e.b}:{e.b_if} ({e.source})",
                    recommendation="The neighbor was seen here via other sources - "
                                   "check cabling, SFP and the far end",
                ))
    return out


def _changes(devices, edges, prev) -> list[Finding]:
    old_devices, old_edges = prev
    d = diff_runs(old_devices, old_edges, devices, edges)
    out = []
    for nid in d["removed_devices"]:
        out.append(Finding(
            rule="topology-change", severity="warning",
            title=f"device disappeared since previous run: {_label(old_devices, nid)}",
            affected=[nid], evidence="present in previous snapshot, absent now",
            recommendation="Confirm decommissioning; otherwise investigate outage",
        ))
    for nid in d["added_devices"]:
        out.append(Finding(
            rule="topology-change", severity="info",
            title=f"new device: {_label(devices, nid)}",
            affected=[nid], evidence="absent in previous snapshot",
            recommendation="Verify the device is expected on this network",
        ))
    for e in d["removed_edges"]:
        out.append(Finding(
            rule="topology-change", severity="warning",
            title=f"link disappeared: {e.a}:{e.a_if} <-> {e.b}:{e.b_if}",
            affected=[e.a, e.b], evidence=f"was discovered via {e.sources}",
            recommendation="Check for failed links or re-cabling",
        ))
    for nid, old_v, new_v in d["version_changes"]:
        out.append(Finding(
            rule="topology-change", severity="info",
            title=f"{_label(devices, nid)} software changed: {old_v} -> {new_v}",
            affected=[nid], evidence=f"previous={old_v}, current={new_v}",
            recommendation="Expected after maintenance; otherwise investigate",
        ))
    for nid, old_s, new_s in d["status_changes"]:
        sev = "warning" if new_s in ("unreachable", "auth_failed", "error") else "info"
        out.append(Finding(
            rule="topology-change", severity=sev,
            title=f"{_label(devices, nid)} status changed: {old_s} -> {new_s}",
            affected=[nid], evidence=f"previous={old_s}, current={new_s}",
            recommendation="Investigate if the device regressed to unreachable",
        ))
    return out
