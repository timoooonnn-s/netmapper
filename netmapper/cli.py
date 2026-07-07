"""netmapper CLI: discover / show / analyze / viz / export / runs."""
from __future__ import annotations

import argparse
import logging
import sys
import webbrowser
from pathlib import Path

from . import __version__, topology, viz_html, viz_term
from .config import Config, ConfigError, get_profile, load_config, resolve_seeds
from .store import RunStore, StoreError


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s" if not args.verbose else "%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    if not args.verbose:
        logging.getLogger("paramiko").setLevel(logging.WARNING)
        logging.getLogger("pysnmp").setLevel(logging.WARNING)
    try:
        cfg = load_config(args.config)
        return args.func(cfg, args)
    except (ConfigError, StoreError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netmapper",
        description="Read-only network topology discovery, visualization and "
                    "troubleshooting - Extreme VOSS/VSP first.")
    p.add_argument("--config", "-c", help="config file (default: ./netmapper.toml if present)")
    p.add_argument("--verbose", "-v", action="store_true", help="debug logging")
    p.add_argument("--version", action="version", version=f"netmapper {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("discover", help="discover topology from seed devices")
    d.add_argument("--seeds", "-s", required=True,
                   help="comma-separated IPs and/or @seed-groups from config")
    d.add_argument("--profile", "-p", help="auth profile name from config")
    d.add_argument("--depth", type=int, help="max hops from seeds (default from config, else 3)")
    d.add_argument("--workers", type=int, help="concurrent device sessions (default 10)")
    d.add_argument("--max-devices", type=int, help="hard cap on discovered devices (default 200)")
    d.add_argument("--arp-limit", type=int, help="max ARP-only candidates per device (default 30)")
    d.set_defaults(func=cmd_discover)

    s = sub.add_parser("show", help="terminal view of a stored run")
    s.add_argument("--run", "-r", default="latest")
    s.add_argument("--device", "-d", help="show one device in detail (name or IP)")
    s.add_argument("--tree", action="store_true", help="neighbor tree instead of table")
    s.set_defaults(func=cmd_show)

    a = sub.add_parser("analyze", help="run analysis rules against a stored run")
    a.add_argument("--run", "-r", default="latest")
    a.add_argument("--compare-to", help="previous run id for topology-change detection")
    a.set_defaults(func=cmd_analyze)

    v = sub.add_parser("viz", help="build the interactive HTML topology")
    v.add_argument("--run", "-r", default="latest")
    v.add_argument("--out", "-o", help="output file (default: <run-dir>/topology.html)")
    v.add_argument("--open", action="store_true", help="open in browser")
    v.set_defaults(func=cmd_viz)

    e = sub.add_parser("export", help="export a run (graphml/dot/mermaid/json)")
    e.add_argument("--run", "-r", default="latest")
    e.add_argument("--format", "-f", required=True,
                   choices=["graphml", "dot", "mermaid", "json"])
    e.add_argument("--out", "-o", help="output file (default: stdout, graphml requires --out)")
    e.set_defaults(func=cmd_export)

    r = sub.add_parser("runs", help="list stored discovery runs")
    r.set_defaults(func=cmd_runs)
    return p


def _store(cfg: Config) -> RunStore:
    return RunStore(cfg.defaults.runs_dir)


# ------------------------------------------------------------------ commands

def cmd_discover(cfg: Config, args) -> int:
    from .engine import DiscoveryEngine  # lazy: pulls in netmiko/pysnmp paths

    seeds = resolve_seeds(cfg, args.seeds)
    if not seeds:
        raise ConfigError("no seeds given")
    profile = get_profile(cfg, args.profile)
    profile.resolve_credentials(interactive=sys.stdin.isatty())

    engine = DiscoveryEngine(
        profile,
        max_depth=args.depth if args.depth is not None else cfg.defaults.depth,
        workers=args.workers or cfg.defaults.workers,
        max_devices=args.max_devices or cfg.defaults.max_devices,
        arp_limit=args.arp_limit if args.arp_limit is not None else cfg.defaults.arp_limit,
    )
    devices, edges, meta = engine.run(seeds)

    store = _store(cfg)
    meta.run_id = store.new_run_id()
    run_dir = store.save_run(meta, devices, edges)

    print()
    print(viz_term.device_table(devices))
    st = meta.stats
    print(f"\n{st['devices']} devices, {st['edges']} links in {st['duration_s']}s "
          f"-> {run_dir}")
    print("next: netmapper analyze && netmapper viz --open")
    return 0


def cmd_show(cfg: Config, args) -> int:
    meta, devices, edges = _store(cfg).load_run(args.run)
    if args.device:
        dev = _find_device(devices, args.device)
        print(viz_term.device_detail(dev, devices, edges))
    elif args.tree:
        print(viz_term.neighbor_tree(devices, edges))
    else:
        print(f"run {meta.run_id} (profile {meta.profile}, seeds {', '.join(meta.seeds)})\n")
        print(viz_term.device_table(devices))
    return 0


def cmd_analyze(cfg: Config, args) -> int:
    from .analysis import analyze

    store = _store(cfg)
    meta, devices, edges = store.load_run(args.run)
    prev = None
    if args.compare_to:
        _, prev_devices, prev_edges = store.load_run(args.compare_to)
        prev = (prev_devices, prev_edges)
    else:
        runs = store.list_runs()
        this_run = store.resolve(args.run)
        earlier = [r for r in runs if r < this_run]
        if earlier:  # auto-diff against the run just before this one
            _, prev_devices, prev_edges = store.load_run(earlier[-1])
            prev = (prev_devices, prev_edges)
            print(f"(comparing against previous run {earlier[-1]})\n", file=sys.stderr)

    findings = analyze(devices, edges, prev)
    store.save_findings(meta.run_id, findings)
    print(viz_term.findings_table(findings))
    return 1 if any(f.severity == "critical" for f in findings) else 0


def cmd_viz(cfg: Config, args) -> int:
    store = _store(cfg)
    meta, devices, edges = store.load_run(args.run)
    findings = store.load_findings(args.run)
    pos = topology.layout(devices, edges)
    html = viz_html.build_html(meta, devices, edges, findings, pos)
    out = Path(args.out) if args.out else store.run_dir(meta.run_id) / "topology.html"
    out.write_text(html)
    print(f"wrote {out}")
    if args.open:
        webbrowser.open(out.resolve().as_uri())
    return 0


def cmd_export(cfg: Config, args) -> int:
    from . import export

    store = _store(cfg)
    meta, devices, edges = store.load_run(args.run)
    if args.format == "graphml":
        if not args.out:
            raise ConfigError("graphml export needs --out FILE")
        export.to_graphml(devices, edges, args.out)
        print(f"wrote {args.out}")
        return 0
    if args.format == "dot":
        text = export.to_dot(devices, edges)
    elif args.format == "mermaid":
        text = export.to_mermaid(devices, edges)
    else:
        text = export.to_json(meta, devices, edges, store.load_findings(args.run))
    if args.out:
        Path(args.out).write_text(text)
        print(f"wrote {args.out}")
    else:
        print(text, end="")
    return 0


def cmd_runs(cfg: Config, args) -> int:
    store = _store(cfg)
    runs = store.list_runs()
    if not runs:
        print("no runs yet")
        return 0
    rows = []
    for r in runs:
        try:
            meta, devices, edges = store.load_run(r)
            rows.append([r, meta.profile, ",".join(meta.seeds[:3]),
                         str(len(devices)), str(len(edges)),
                         str(meta.stats.get("duration_s", "?")) + "s"])
        except StoreError:
            rows.append([r, "?", "?", "?", "?", "?"])
    print(viz_term.table(["RUN", "PROFILE", "SEEDS", "DEVICES", "LINKS", "TOOK"], rows))
    return 0


def _find_device(devices, ref: str):
    ref_l = ref.lower()
    for d in devices.values():
        if d.mgmt_ip == ref or d.label.lower() == ref_l:
            return d
    matches = [d for d in devices.values() if ref_l in d.label.lower() or ref in d.mgmt_ip]
    if len(matches) == 1:
        return matches[0]
    raise StoreError(
        f"device '{ref}' not found" if not matches
        else f"'{ref}' is ambiguous: {', '.join(m.label for m in matches[:8])}")


if __name__ == "__main__":
    raise SystemExit(main())
