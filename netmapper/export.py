"""Exports: GraphML (yEd/Gephi), Graphviz DOT, Mermaid, combined JSON."""
from __future__ import annotations

import json
from pathlib import Path

from .models import Device, Edge, to_dict
from .topology import build_graph

TYPE_COLORS = {
    "switch": "#4c9be8", "router": "#8f6fe8", "firewall": "#e8734c",
    "server": "#4ce89b", "endpoint": "#9aa5b1", "iot": "#e8c94c", "unknown": "#c0c7d0",
}


def to_graphml(devices: dict[str, Device], edges: list[Edge], path: str | Path) -> None:
    import networkx as nx
    g = build_graph(devices, edges)
    nx.write_graphml(g, str(path))


def to_dot(devices: dict[str, Device], edges: list[Edge]) -> str:
    lines = ["graph netmapper {",
             '  layout=neato; overlap=false; splines=true;',
             '  node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=10];']
    for nid, d in devices.items():
        label = d.label
        if d.model:
            label += f"\\n{d.model}"
        if d.mgmt_ip and d.mgmt_ip != d.label:
            label += f"\\n{d.mgmt_ip}"
        color = TYPE_COLORS.get(d.device_type, TYPE_COLORS["unknown"])
        style = ', style="rounded,filled,dashed"' if d.status in ("stub", "ping_only") else ""
        lines.append(f'  "{nid}" [label="{label}", fillcolor="{color}"{style}];')
    for e in edges:
        attrs = []
        if e.a_if or e.b_if:
            attrs.append(f'label="{e.a_if} - {e.b_if}", fontsize=8')
        if e.confidence < 0.6:
            attrs.append('style=dashed')
        lines.append(f'  "{e.a}" -- "{e.b}"' + (f' [{", ".join(attrs)}]' if attrs else "") + ";")
    lines.append("}")
    return "\n".join(lines) + "\n"


def to_mermaid(devices: dict[str, Device], edges: list[Edge]) -> str:
    ids = {nid: f"n{i}" for i, nid in enumerate(devices)}
    lines = ["graph TD"]
    for nid, d in devices.items():
        text = d.label + (f"<br/>{d.mgmt_ip}" if d.mgmt_ip and d.mgmt_ip != d.label else "")
        lines.append(f'  {ids[nid]}["{text}"]')
    for e in edges:
        if e.a not in ids or e.b not in ids:
            continue
        if e.a_if or e.b_if:
            lines.append(f'  {ids[e.a]} ---|"{e.a_if or "?"} - {e.b_if or "?"}"| {ids[e.b]}')
        else:
            lines.append(f"  {ids[e.a]} --- {ids[e.b]}")
    return "\n".join(lines) + "\n"


def to_json(meta, devices: dict[str, Device], edges: list[Edge], findings=None) -> str:
    return json.dumps({
        "run": to_dict(meta),
        "devices": [to_dict(d) for d in devices.values()],
        "edges": [to_dict(e) for e in edges],
        "findings": [to_dict(f) for f in findings] if findings else [],
    }, indent=2) + "\n"
