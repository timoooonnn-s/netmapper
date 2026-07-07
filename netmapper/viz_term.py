"""Terminal views: plain-text tables and a neighbor tree. No dependencies."""
from __future__ import annotations

from .models import Device, Edge, Finding

STATUS_MARK = {"ok": "+", "ping_only": "~", "stub": "?",
               "unreachable": "!", "auth_failed": "!", "error": "!"}


def table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    out = [fmt.format(*headers), fmt.format(*("-" * w for w in widths))]
    out += [fmt.format(*(str(c) for c in row)) for row in rows]
    return "\n".join(out)


def device_table(devices: dict[str, Device]) -> str:
    rows = []
    for d in sorted(devices.values(), key=lambda x: (x.depth, x.label)):
        rows.append([
            STATUS_MARK.get(d.status, " ") + " " + d.label, d.mgmt_ip, d.vendor,
            d.model, d.sw_version, d.device_type, d.status, str(d.depth),
        ])
    legend = "  (+ ok  ~ ping-only  ? stub  ! problem)"
    return table(["DEVICE", "MGMT IP", "VENDOR", "MODEL", "VERSION", "TYPE", "STATUS", "DEPTH"],
                 rows) + "\n" + legend


def device_detail(dev: Device, devices: dict[str, Device], edges: list[Edge]) -> str:
    out = [f"{dev.label}  ({dev.mgmt_ip})",
           f"  vendor:  {dev.vendor}   model: {dev.model}   version: {dev.sw_version}",
           f"  type:    {dev.device_type}   status: {dev.status}   depth: {dev.depth}"
           f"   rtt: {dev.rtt_ms} ms   plugin: {dev.plugin}"]
    if dev.aliases:
        out.append(f"  aliases: {', '.join(dev.aliases)}")
    if dev.errors:
        out.append(f"  errors:  {'; '.join(dev.errors[:5])}")
    mine = [e for e in edges if dev.node_id in (e.a, e.b)]
    if mine:
        out.append(f"\n  Links ({len(mine)}):")
        rows = []
        for e in sorted(mine, key=lambda e: -e.confidence):
            other = e.b if e.a == dev.node_id else e.a
            lif = e.a_if if e.a == dev.node_id else e.b_if
            rif = e.b_if if e.a == dev.node_id else e.a_if
            od = devices.get(other)
            rows.append([lif or "-", (od.label if od else other), rif or "-",
                         "/".join(e.sources), f"{e.confidence:.2f}",
                         ",".join(e.tags) or "-"])
        out.append("    " + table(["LOCAL IF", "NEIGHBOR", "REMOTE IF", "SOURCES", "CONF", "TAGS"],
                                  rows).replace("\n", "\n    "))
    if dev.interfaces:
        up = sum(1 for i in dev.interfaces if i.oper_status == "up")
        out.append(f"\n  Interfaces: {len(dev.interfaces)} total, {up} up")
    if dev.routes:
        out.append(f"  Routes: {len(dev.routes)}")
    return "\n".join(out)


def neighbor_tree(devices: dict[str, Device], edges: list[Edge],
                  root: str | None = None) -> str:
    adj: dict[str, list[str]] = {}
    for e in edges:
        adj.setdefault(e.a, []).append(e.b)
        adj.setdefault(e.b, []).append(e.a)
    if root is None:
        seeds = [nid for nid, d in devices.items() if d.depth == 0 and d.status == "ok"]
        root = seeds[0] if seeds else (next(iter(devices), None))
    if root is None:
        return "(empty topology)"

    def label(nid: str) -> str:
        d = devices.get(nid)
        return f"{d.label} [{d.device_type}/{d.status}]" if d else nid

    out: list[str] = [label(root)]
    seen: set[str] = {root}

    def walk(nid: str, prefix: str) -> None:
        kids = [k for k in sorted(set(adj.get(nid, []))) if k not in seen]
        seen.update(kids)
        for i, k in enumerate(kids):
            last = i == len(kids) - 1
            out.append(prefix + ("`- " if last else "|- ") + label(k))
            walk(k, prefix + ("   " if last else "|  "))

    walk(root, "")
    orphans = set(devices) - seen
    if orphans:
        out.append(f"\n(not connected to {devices[root].label}: "
                   f"{', '.join(devices[o].label for o in sorted(orphans))})")
    return "\n".join(out)


def findings_table(findings: list[Finding]) -> str:
    if not findings:
        return "No findings - topology looks clean."
    out = []
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    out.append("  ".join(f"{sev.upper()}: {n}" for sev, n in
                         sorted(counts.items(), key=lambda x: x[0])) + "\n")
    for f in findings:
        out.append(f"[{f.severity.upper():8}] {f.rule}: {f.title}")
        if f.evidence:
            out.append(f"           evidence:       {f.evidence}")
        if f.recommendation:
            out.append(f"           recommendation: {f.recommendation}")
        out.append("")
    return "\n".join(out)
