"""Interactive topology viewer: one self-contained HTML file.

Plain SVG + vanilla JavaScript, zero external resources (no CDN, no fonts,
no fetches), so it opens from file:// under restrictive corporate browser
policies. Layout is precomputed in Python; the JS only renders and interacts.
"""
from __future__ import annotations

import json

from .models import Device, Edge, Finding, RunMeta, to_dict


def build_html(meta: RunMeta, devices: dict[str, Device], edges: list[Edge],
               findings: list[Finding] | None,
               positions: dict[str, tuple[float, float]]) -> str:
    nodes = []
    for nid, d in devices.items():
        x, y = positions.get(nid, (0, 0))
        nodes.append({
            "id": nid, "label": d.label, "ip": d.mgmt_ip, "x": x, "y": y,
            "type": d.device_type, "status": d.status, "vendor": d.vendor,
            "model": d.model, "version": d.sw_version, "depth": d.depth,
            "plugin": d.plugin, "errors": d.errors[:5],
            "n_if": len(d.interfaces), "n_routes": len(d.routes),
        })
    data = {
        "meta": to_dict(meta),
        "nodes": nodes,
        "edges": [to_dict(e) for e in edges],
        "findings": [to_dict(f) for f in (findings or [])],
    }
    return _TEMPLATE.replace("__DATA__", json.dumps(data))


_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>NetMapper topology</title>
<style>
  :root {
    --bg:#12161c; --panel:#1b222c; --line:#2d3947; --text:#dbe4ee; --dim:#8b98a8;
    --switch:#4c9be8; --router:#8f6fe8; --firewall:#e8734c; --server:#4ce89b;
    --endpoint:#9aa5b1; --iot:#e8c94c; --unknown:#5c6875;
    --crit:#ff5c5c; --warn:#e8b84c; --info:#6aa9e8;
  }
  * { box-sizing:border-box; margin:0; }
  body { background:var(--bg); color:var(--text);
         font:13px/1.45 system-ui,Segoe UI,Helvetica,Arial,sans-serif;
         overflow:hidden; height:100vh; display:flex; }
  #svgwrap { flex:1; position:relative; }
  svg { width:100%; height:100%; display:block; cursor:grab; }
  svg.panning { cursor:grabbing; }
  #toolbar { position:absolute; top:10px; left:10px; background:var(--panel);
             border:1px solid var(--line); border-radius:8px; padding:8px 10px;
             display:flex; gap:10px; align-items:center; flex-wrap:wrap; max-width:70%; }
  #toolbar input[type=search] { background:var(--bg); color:var(--text);
             border:1px solid var(--line); border-radius:5px; padding:4px 8px; width:170px; }
  #toolbar label { color:var(--dim); font-size:12px; display:flex; gap:5px; align-items:center; }
  #legend { position:absolute; bottom:10px; left:10px; background:var(--panel);
            border:1px solid var(--line); border-radius:8px; padding:8px 12px;
            font-size:11px; color:var(--dim); }
  #legend span.dot { display:inline-block; width:9px; height:9px; border-radius:50%;
                     margin:0 4px 0 10px; vertical-align:baseline; }
  #panel { width:340px; background:var(--panel); border-left:1px solid var(--line);
           padding:14px; overflow-y:auto; }
  #panel h1 { font-size:15px; margin-bottom:2px; }
  #panel h2 { font-size:12px; color:var(--dim); text-transform:uppercase;
              letter-spacing:.06em; margin:16px 0 6px; }
  #panel .kv { color:var(--dim); }
  #panel .kv b { color:var(--text); font-weight:500; }
  #panel table { border-collapse:collapse; width:100%; font-size:12px; }
  #panel td { padding:2px 6px 2px 0; vertical-align:top; }
  #panel .link { cursor:pointer; color:var(--info); }
  .finding { border-left:3px solid var(--info); padding:5px 8px; margin:6px 0;
             background:rgba(255,255,255,.03); border-radius:0 5px 5px 0; }
  .finding.critical { border-color:var(--crit); }
  .finding.warning  { border-color:var(--warn); }
  .finding .sev { font-size:10px; text-transform:uppercase; letter-spacing:.05em; color:var(--dim); }
  .finding .rec { color:var(--dim); font-size:12px; margin-top:2px; }
  .edge { stroke:var(--line); stroke-width:1.6; }
  .edge.hi { stroke:#e8e05c; stroke-width:2.6; }
  .edge.low { stroke-dasharray:5 4; }
  .edge.hidden, .node.hidden { display:none; }
  .node { cursor:pointer; }
  .node circle { stroke:#0009; stroke-width:1.2; }
  .node.problem circle { stroke:var(--crit); stroke-width:2.5; }
  .node.ghost circle { stroke-dasharray:3 3; stroke:var(--dim); fill-opacity:.35; }
  .node text { fill:var(--text); font-size:11px; text-anchor:middle;
               paint-order:stroke; stroke:var(--bg); stroke-width:3px; }
  .node.dim { opacity:.18; } .edge.dim { opacity:.1; }
  .node.sel circle { stroke:#fff; stroke-width:2.5; }
</style>
</head>
<body>
<div id="svgwrap">
  <svg id="svg"><g id="vp"></g></svg>
  <div id="toolbar">
    <strong>NetMapper</strong>
    <input id="search" type="search" placeholder="find device / IP / model">
    <label>min confidence <input id="conf" type="range" min="0" max="100" value="0" style="width:90px">
      <span id="confv">0</span></label>
    <label><input id="showstubs" type="checkbox" checked> stubs/endpoints</label>
  </div>
  <div id="legend"></div>
</div>
<div id="panel"><h1>Topology</h1><div id="pbody"></div></div>
<script>
"use strict";
const DATA = __DATA__;
const COLORS = {switch:"var(--switch)",router:"var(--router)",firewall:"var(--firewall)",
                server:"var(--server)",endpoint:"var(--endpoint)",iot:"var(--iot)",
                unknown:"var(--unknown)"};
const NS = "http://www.w3.org/2000/svg";
const svg = document.getElementById("svg"), vp = document.getElementById("vp");
const nodesById = {}; DATA.nodes.forEach(n => nodesById[n.id] = n);
const findingsByNode = {};
DATA.findings.forEach(f => (f.affected||[]).forEach(a => (findingsByNode[a] ||= []).push(f)));

function el(tag, attrs, parent) {
  const e = document.createElementNS(NS, tag);
  for (const k in attrs) e.setAttribute(k, attrs[k]);
  if (parent) parent.appendChild(e);
  return e;
}
function esc(s) { const d = document.createElement("span"); d.textContent = s ?? ""; return d.innerHTML; }

/* ---- edges ---- */
const edgeEls = [];
DATA.edges.forEach(e => {
  const a = nodesById[e.a], b = nodesById[e.b];
  if (!a || !b) return;
  const ln = el("line", {class:"edge" + (e.confidence >= 0.9 ? " hi" : e.confidence < 0.6 ? " low" : ""),
                         x1:a.x, y1:a.y, x2:b.x, y2:b.y}, vp);
  el("title", {}, ln).textContent =
    `${a.label} ${e.a_if||""}  <->  ${b.label} ${e.b_if||""}\n` +
    `sources: ${e.sources.join(", ")}   confidence: ${e.confidence}` +
    (e.tags.length ? `\ntags: ${e.tags.join(", ")}` : "");
  edgeEls.push({e, ln, a, b});
});

/* ---- nodes ---- */
const nodeEls = {};
DATA.nodes.forEach(n => {
  const ghost = (n.status === "stub" || n.status === "ping_only");
  const problem = ["unreachable","auth_failed","error"].includes(n.status);
  const g = el("g", {class:"node" + (ghost ? " ghost" : "") + (problem ? " problem" : ""),
                     transform:`translate(${n.x},${n.y})`, "data-id":n.id}, vp);
  const r = (n.type === "endpoint" || n.type === "iot") ? 7 : 11;
  el("circle", {r, fill: COLORS[n.type] || COLORS.unknown}, g);
  if ((findingsByNode[n.id]||[]).some(f => f.severity !== "info"))
    el("circle", {r: r + 4, fill:"none", stroke:"var(--warn)", "stroke-width":1.4,
                  "stroke-dasharray":"2 2"}, g);
  const t = el("text", {y: r + 13}, g); t.textContent = n.label;
  nodeEls[n.id] = {n, g};
});

/* ---- pan / zoom / drag ---- */
let view = {x:0, y:0, k:1}, drag = null;
function apply() { vp.setAttribute("transform", `translate(${view.x},${view.y}) scale(${view.k})`); }
function toWorld(ev) {
  const r = svg.getBoundingClientRect();
  return {x:(ev.clientX - r.left - view.x)/view.k, y:(ev.clientY - r.top - view.y)/view.k};
}
svg.addEventListener("wheel", ev => {
  ev.preventDefault();
  const f = ev.deltaY < 0 ? 1.15 : 1/1.15, p = toWorld(ev);
  view.k = Math.max(.08, Math.min(8, view.k * f));
  const r = svg.getBoundingClientRect();
  view.x = ev.clientX - r.left - p.x * view.k;
  view.y = ev.clientY - r.top - p.y * view.k;
  apply();
}, {passive:false});
/* Note: setPointerCapture retargets the derived click event, so selection is
   decided in pointerup (click vs drag, by movement) rather than via click. */
svg.addEventListener("pointerdown", ev => {
  const hit = ev.target.closest(".node");
  drag = {cx:ev.clientX, cy:ev.clientY, moved:false};
  if (hit) {
    drag.node = nodeEls[hit.dataset.id];
  } else {
    drag.pan = true;
    drag.sx = ev.clientX - view.x; drag.sy = ev.clientY - view.y;
    svg.classList.add("panning");
  }
  svg.setPointerCapture(ev.pointerId);
});
svg.addEventListener("pointermove", ev => {
  if (!drag) return;
  if (Math.abs(ev.clientX - drag.cx) + Math.abs(ev.clientY - drag.cy) > 3) drag.moved = true;
  if (!drag.moved) return;
  if (drag.pan) { view.x = ev.clientX - drag.sx; view.y = ev.clientY - drag.sy; apply(); return; }
  const p = toWorld(ev), n = drag.node.n;
  n.x = p.x; n.y = p.y;
  drag.node.g.setAttribute("transform", `translate(${n.x},${n.y})`);
  edgeEls.forEach(({e, ln}) => {
    if (e.a === n.id) { ln.setAttribute("x1", n.x); ln.setAttribute("y1", n.y); }
    if (e.b === n.id) { ln.setAttribute("x2", n.x); ln.setAttribute("y2", n.y); }
  });
});
svg.addEventListener("pointerup", () => {
  if (drag && !drag.moved) select(drag.node ? drag.node.n.id : null);
  drag = null;
  svg.classList.remove("panning");
});

function fit() {
  if (!DATA.nodes.length) return;
  const xs = DATA.nodes.map(n => n.x), ys = DATA.nodes.map(n => n.y);
  const minx = Math.min(...xs) - 60, maxx = Math.max(...xs) + 60;
  const miny = Math.min(...ys) - 60, maxy = Math.max(...ys) + 60;
  const r = svg.getBoundingClientRect();
  view.k = Math.min(r.width/(maxx - minx), r.height/(maxy - miny), 2);
  view.x = (r.width - (minx + maxx) * view.k) / 2;
  view.y = (r.height - (miny + maxy) * view.k) / 2;
  apply();
}
window.addEventListener("resize", fit);

/* ---- filters ---- */
const searchBox = document.getElementById("search");
const confSlider = document.getElementById("conf");
const showStubs = document.getElementById("showstubs");
function refilter() {
  const q = searchBox.value.trim().toLowerCase();
  const minConf = confSlider.value / 100;
  document.getElementById("confv").textContent = confSlider.value / 100;
  const visible = {};
  DATA.nodes.forEach(n => {
    const ghost = (n.status === "stub" || (n.type === "endpoint" && n.status !== "ok"));
    visible[n.id] = showStubs.checked || !ghost;
    nodeEls[n.id].g.classList.toggle("hidden", !visible[n.id]);
    const hit = q && [n.label, n.ip, n.model, n.vendor, n.version].join(" ").toLowerCase().includes(q);
    nodeEls[n.id].g.classList.toggle("dim", q && !hit);
  });
  edgeEls.forEach(({e, ln}) => {
    ln.classList.toggle("hidden",
      e.confidence < minConf || !visible[e.a] || !visible[e.b]);
    ln.classList.toggle("dim", !!q);
  });
}
[searchBox, confSlider, showStubs].forEach(x => x.addEventListener("input", refilter));

/* ---- side panel ---- */
const pbody = document.getElementById("pbody");
function select(id) {
  document.querySelectorAll(".node.sel").forEach(x => x.classList.remove("sel"));
  if (!id) { overview(); return; }
  nodeEls[id].g.classList.add("sel");
  const n = nodesById[id];
  let h = `<h1>${esc(n.label)}</h1><div class="kv">${esc(n.ip)}</div>
    <h2>Device</h2><table>
    <tr><td class="kv">vendor</td><td>${esc(n.vendor)||"-"}</td></tr>
    <tr><td class="kv">model</td><td>${esc(n.model)||"-"}</td></tr>
    <tr><td class="kv">version</td><td>${esc(n.version)||"-"}</td></tr>
    <tr><td class="kv">type / status</td><td>${esc(n.type)} / ${esc(n.status)}</td></tr>
    <tr><td class="kv">depth / plugin</td><td>${n.depth} / ${esc(n.plugin)||"-"}</td></tr>
    <tr><td class="kv">interfaces</td><td>${n.n_if} (routes: ${n.n_routes})</td></tr></table>`;
  if (n.errors.length)
    h += `<h2>Collection errors</h2><div class="kv">${n.errors.map(esc).join("<br>")}</div>`;
  const links = edgeEls.filter(({e}) => e.a === id || e.b === id);
  h += `<h2>Links (${links.length})</h2><table>`;
  links.sort((p,q) => q.e.confidence - p.e.confidence).forEach(({e}) => {
    const other = e.a === id ? e.b : e.a;
    const lif = e.a === id ? e.a_if : e.b_if, rif = e.a === id ? e.b_if : e.a_if;
    h += `<tr><td class="kv">${esc(lif)||"-"}</td>
      <td><span class="link" data-id="${esc(other)}">${esc(nodesById[other]?.label||other)}</span>
      <span class="kv">${esc(rif)||""}</span></td>
      <td class="kv">${esc(e.sources.join("/"))} ${e.confidence}</td></tr>`;
  });
  h += "</table>";
  const fs = findingsByNode[id] || [];
  if (fs.length) { h += `<h2>Findings (${fs.length})</h2>` + fs.map(fBox).join(""); }
  pbody.innerHTML = h;
  pbody.querySelectorAll(".link").forEach(x =>
    x.addEventListener("click", () => { select(x.dataset.id); center(x.dataset.id); }));
}
function fBox(f) {
  return `<div class="finding ${f.severity}"><div class="sev">${esc(f.severity)} - ${esc(f.rule)}</div>
    <div>${esc(f.title)}</div><div class="rec">${esc(f.recommendation)}</div></div>`;
}
function center(id) {
  const n = nodesById[id], r = svg.getBoundingClientRect();
  view.x = r.width/2 - n.x*view.k; view.y = r.height/2 - n.y*view.k; apply();
}
function overview() {
  const m = DATA.meta, counts = {};
  DATA.nodes.forEach(n => counts[n.status] = (counts[n.status]||0)+1);
  let h = `<h1>Run ${esc(m.run_id)}</h1>
    <div class="kv">profile <b>${esc(m.profile)}</b>, depth ${m.max_depth},
      seeds: ${m.seeds.map(esc).join(", ")}</div>
    <h2>Inventory</h2><table>
    <tr><td class="kv">devices</td><td>${DATA.nodes.length}</td></tr>
    <tr><td class="kv">links</td><td>${DATA.edges.length}</td></tr>` +
    Object.entries(counts).map(([s,c]) => `<tr><td class="kv">${esc(s)}</td><td>${c}</td></tr>`).join("") +
    "</table>";
  if (DATA.findings.length) {
    h += `<h2>Findings (${DATA.findings.length})</h2>` + DATA.findings.map(f => {
      const first = (f.affected||[])[0];
      return `<div class="finding ${f.severity}" ${first?`data-id="${esc(first)}" style="cursor:pointer"`:""}>
        <div class="sev">${esc(f.severity)} - ${esc(f.rule)}</div><div>${esc(f.title)}</div></div>`;
    }).join("");
  } else {
    h += `<h2>Findings</h2><div class="kv">none recorded (run "netmapper analyze")</div>`;
  }
  h += `<h2>Tips</h2><div class="kv">scroll = zoom, drag background = pan,
    drag node = move, click node = details</div>`;
  pbody.innerHTML = h;
  pbody.querySelectorAll(".finding[data-id]").forEach(x =>
    x.addEventListener("click", () => { select(x.dataset.id); center(x.dataset.id); }));
}

/* ---- legend ---- */
document.getElementById("legend").innerHTML =
  Object.entries(COLORS).map(([t,c]) =>
    `<span class="dot" style="background:${c}"></span>${t}`).join("") +
  `<br><span style="border-bottom:2px solid var(--line)">&nbsp;&nbsp;&nbsp;</span> link
   <span style="border-bottom:2px dashed var(--line)">&nbsp;&nbsp;&nbsp;</span> low confidence
   <span style="border-bottom:2px solid #e8e05c">&nbsp;&nbsp;&nbsp;</span> LLDP/fabric`;

overview(); refilter(); fit();
</script>
</body>
</html>
"""
