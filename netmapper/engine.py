"""Discovery engine: breadth-first walk from the seed devices.

Each depth wave probes its devices concurrently in a thread pool (netmiko is
synchronous, and 10-20 worker threads comfortably cover 100+ devices). New
management IPs learned from LLDP / ISIS / vIST / FDB / routes / ARP feed the
next wave until max depth or the device cap is hit.
"""
from __future__ import annotations

import datetime
import ipaddress
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import topology, transports
from .config import Profile
from .fingerprint import plugin_for_netmiko, select_plugin
from .models import Device, Edge, NeighborCandidate, RunMeta, norm_hostname
from .plugins.base import CollectContext
from .plugins.generic import GenericPlugin, OID_SYSDESCR, OID_SYSNAME

log = logging.getLogger("netmapper.engine")


def usable_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_multicast or a.is_loopback or a.is_unspecified
                or a.is_link_local or a.is_reserved)


class DiscoveryEngine:
    def __init__(self, profile: Profile, max_depth: int = 3, workers: int = 10,
                 max_devices: int = 200, arp_limit: int = 30):
        self.profile = profile
        self.max_depth = max_depth
        self.workers = workers
        self.max_devices = max_devices
        self.arp_limit = arp_limit

    # ------------------------------------------------------------ run

    def run(self, seeds: list[str]) -> tuple[dict[str, Device], list[Edge], RunMeta]:
        started = time.monotonic()
        meta = RunMeta(
            run_id="", started=datetime.datetime.now().astimezone().isoformat(),
            profile=self.profile.name, seeds=list(seeds), max_depth=self.max_depth,
        )
        devices: dict[str, Device] = {}
        hostname_seen: dict[str, str] = {}
        visited: set[str] = set()
        frontier = [s for s in seeds if usable_ip(s)]
        for bad in set(seeds) - set(frontier):
            log.warning("skipping invalid seed %r", bad)
        visited.update(frontier)
        depth = 0

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            while frontier and depth <= self.max_depth:
                log.info("depth %d: probing %d device(s)", depth, len(frontier))
                futures = {pool.submit(self._probe, ip, depth): ip for ip in frontier}
                wave: list[Device] = []
                for fut in as_completed(futures):
                    dev = fut.result()  # _probe never raises
                    hn = norm_hostname(dev.hostname)
                    if hn and hn in hostname_seen and dev.mgmt_ip != hostname_seen[hn]:
                        # Same box reached via a second IP - merge as alias.
                        devices[hostname_seen[hn]].aliases.append(dev.mgmt_ip)
                        log.info("%s is an alias of %s (%s)", dev.mgmt_ip, hostname_seen[hn], hn)
                        continue
                    if hn:
                        hostname_seen[hn] = dev.node_id
                    devices[dev.node_id] = dev
                    wave.append(dev)
                    log.info("  %-15s %-10s %s %s", dev.mgmt_ip, dev.status,
                             dev.label, dev.model)
                depth += 1
                frontier = self._next_frontier(wave, devices, visited, depth)

        edges, stubs = topology.build_edges(devices)
        devices.update(stubs)

        by_status: dict[str, int] = {}
        for d in devices.values():
            by_status[d.status] = by_status.get(d.status, 0) + 1
        meta.finished = datetime.datetime.now().astimezone().isoformat()
        meta.stats = {
            "devices": len(devices), "edges": len(edges),
            "by_status": by_status, "duration_s": round(time.monotonic() - started, 1),
        }
        return devices, edges, meta

    # ------------------------------------------------------------ frontier

    def _next_frontier(self, wave: list[Device], devices: dict[str, Device],
                       visited: set[str], next_depth: int) -> list[str]:
        if next_depth > self.max_depth:
            return []
        name_index = {norm_hostname(d.hostname): d.mgmt_ip
                      for d in devices.values() if d.hostname}
        mac_index = {a.mac: a.ip for d in devices.values() for a in d.arp if a.mac and a.ip}
        out: list[str] = []
        for dev in wave:
            for c in dev.neighbors:
                ip = c.remote_ip
                if not ip and c.remote_mac:
                    ip = mac_index.get(c.remote_mac, "")
                    if ip:
                        c.remote_ip = ip  # remember for edge resolution
                if not ip and c.remote_hostname:
                    ip = name_index.get(norm_hostname(c.remote_hostname), "")
                if not ip or ip in visited or not usable_ip(ip):
                    continue
                if len(devices) + len(out) >= self.max_devices:
                    log.warning("device cap (%d) reached - not expanding further",
                                self.max_devices)
                    return out
                visited.add(ip)
                out.append(ip)
        return out

    # ------------------------------------------------------------ probe

    def _probe(self, ip: str, depth: int) -> Device:
        dev = Device(mgmt_ip=ip, depth=depth)
        try:
            self._probe_inner(dev)
        except transports.ReadOnlyViolation:
            raise  # plugin bug: abort loudly rather than risk writes
        except Exception as exc:  # noqa: BLE001 - a device failure must not kill the run
            dev.status = "error"
            dev.errors.append(str(exc))
            log.debug("probe %s crashed: %s", ip, exc, exc_info=True)
        self._synthesize(dev)
        if dev.hostname:
            dev.hostname = dev.hostname.strip().strip('"')
        return dev

    def _probe_inner(self, dev: Device) -> None:
        p = self.profile
        dev.rtt_ms = transports.ping(dev.mgmt_ip)

        # 1) fingerprint: SNMP sysDescr preferred, netmiko autodetect as fallback
        if p.snmp and p.snmp.usable:
            vals = transports.snmp_get(dev.mgmt_ip, p.snmp, [OID_SYSDESCR, OID_SYSNAME])
            dev.sys_descr = vals.get(OID_SYSDESCR, "")
            dev.hostname = vals.get(OID_SYSNAME, "")
        plugin_cls = None
        if dev.sys_descr:
            plugin_cls = select_plugin(dev.sys_descr)
        if plugin_cls in (None, GenericPlugin) and p.username and p.password:
            try:
                guess = transports.ssh_autodetect(
                    dev.mgmt_ip, p.username, p.password, p.ssh_port, p.ssh_timeout)
            except transports.AuthError:
                dev.status = "auth_failed"
                dev.errors.append("SSH authentication failed")
                return
            plugin_cls = plugin_for_netmiko(guess) or plugin_cls

        ctx = CollectContext(snmp_host=dev.mgmt_ip, snmp=p.snmp)

        # 2) collect over SSH if the plugin speaks CLI
        if plugin_cls and plugin_cls.netmiko_device_type:
            try:
                with transports.SSHSession(
                        dev.mgmt_ip, plugin_cls.netmiko_device_type,
                        p.username, p.password, p.ssh_port, p.ssh_timeout) as ssh:
                    ctx.ssh = ssh
                    plugin_cls().collect(dev, ctx)
                dev.status = "ok"
                return
            except transports.AuthError:
                dev.status = "auth_failed"
                dev.errors.append("SSH authentication failed")
                return
            except transports.SSHError as exc:
                dev.errors.append(str(exc))
                ctx.ssh = None  # fall through to SNMP-only

        # 3) SNMP-only fallback
        if dev.sys_descr:
            GenericPlugin().collect(dev, ctx)
            dev.status = "ok"
            return

        dev.status = "ping_only" if dev.rtt_ms is not None else "unreachable"

    # ------------------------------------------------------------ candidate synthesis

    def _synthesize(self, dev: Device) -> None:
        """Turn FDB / routing / ARP tables into neighbor candidates, in
        priority order, without duplicating what LLDP already covers."""
        lldp_ports = {c.local_interface for c in dev.neighbors
                      if c.source in ("lldp", "isis") and c.local_interface}
        own_macs = {i.mac for i in dev.interfaces if i.mac}
        own_ips = {dev.mgmt_ip} | {ip.split("/")[0] for i in dev.interfaces for ip in i.ips}
        arp_by_mac = {a.mac: a.ip for a in dev.arp}

        # FDB: hosts behind access ports (skip uplinks and busy ports)
        by_port: dict[str, list] = {}
        for f in dev.fdb:
            by_port.setdefault(f.port, []).append(f)
        for port, entries in by_port.items():
            if port in lldp_ports or len(entries) > 5:
                continue
            for f in entries:
                if f.mac in own_macs:
                    continue
                dev.neighbors.append(NeighborCandidate(
                    local_interface=port, remote_mac=f.mac,
                    remote_ip=arp_by_mac.get(f.mac, ""), source="fdb"))

        # Routes: every distinct next hop is a router neighbor
        seen_nh: set[str] = set()
        for r in dev.routes:
            nh = r.next_hop
            if nh and nh not in seen_nh and nh not in own_ips and usable_ip(nh):
                seen_nh.add(nh)
                dev.neighbors.append(NeighborCandidate(
                    remote_ip=nh, source="route",
                    remote_descr=f"next-hop for {r.prefix}"))

        # ARP leftovers, capped so a busy gateway can't flood the graph
        covered_ips = {c.remote_ip for c in dev.neighbors if c.remote_ip}
        covered_macs = {c.remote_mac for c in dev.neighbors if c.remote_mac}
        count = 0
        for a in dev.arp:
            if count >= self.arp_limit:
                break
            if (a.ip in covered_ips or a.mac in covered_macs
                    or a.mac in own_macs or a.ip in own_ips or not usable_ip(a.ip)):
                continue
            dev.neighbors.append(NeighborCandidate(
                local_interface=a.port, remote_ip=a.ip, remote_mac=a.mac, source="arp"))
            count += 1
