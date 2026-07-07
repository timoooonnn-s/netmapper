"""Transports: SSH (netmiko) with a hard read-only guard, SNMP (pysnmp), ICMP ping.

netmiko and pysnmp are imported lazily so the rest of the tool (viz, analysis,
exports, tests) works without them installed.
"""
from __future__ import annotations

import asyncio
import logging
import subprocess
import sys
import time

from .config import SnmpSettings

log = logging.getLogger("netmapper.transports")


# ---------------------------------------------------------------- read-only guard

class ReadOnlyViolation(Exception):
    """A plugin tried to send something that is not a read command."""


# Every command any plugin sends must start with one of these.
ALLOWED_COMMAND_PREFIXES = (
    "show", "display", "get ", "diagnose ", "traceroute", "cpstat", "fw stat",
)


def ensure_read_only(command: str) -> None:
    c = (command or "").strip().lower()
    if not any(c == p.strip() or c.startswith(p) for p in ALLOWED_COMMAND_PREFIXES):
        raise ReadOnlyViolation(f"blocked non-read command: {command!r}")


# ---------------------------------------------------------------- SSH

class SSHError(Exception):
    pass


class AuthError(SSHError):
    pass


class SSHSession:
    """Thin wrapper around netmiko; every command passes the read-only guard."""

    def __init__(self, host: str, device_type: str, username: str, password: str,
                 port: int = 22, timeout: int = 15):
        self.host = host
        self.device_type = device_type
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self._conn = None

    def open(self) -> "SSHSession":
        from netmiko import ConnectHandler
        from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
        try:
            self._conn = ConnectHandler(
                device_type=self.device_type, host=self.host,
                username=self.username, password=self.password,
                port=self.port, conn_timeout=self.timeout,
                auth_timeout=self.timeout, banner_timeout=self.timeout,
            )
        except NetmikoAuthenticationException as exc:
            raise AuthError(f"{self.host}: authentication failed") from exc
        except NetmikoTimeoutException as exc:
            raise SSHError(f"{self.host}: SSH connect timeout") from exc
        except Exception as exc:
            raise SSHError(f"{self.host}: SSH connect failed: {exc}") from exc
        return self

    def send(self, command: str, timeout: int = 30) -> str:
        ensure_read_only(command)
        if self._conn is None:
            raise SSHError("session not open")
        try:
            return self._conn.send_command(command, read_timeout=timeout)
        except ReadOnlyViolation:
            raise
        except Exception as exc:
            raise SSHError(f"{self.host}: '{command}' failed: {exc}") from exc

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.disconnect()
            except Exception:
                pass
            self._conn = None

    def __enter__(self) -> "SSHSession":
        return self.open()

    def __exit__(self, *exc) -> None:
        self.close()


def ssh_autodetect(host: str, username: str, password: str,
                   port: int = 22, timeout: int = 15) -> str | None:
    """Best-effort netmiko device_type guess. Raises AuthError on bad credentials."""
    from netmiko import SSHDetect
    from netmiko.exceptions import NetmikoAuthenticationException
    try:
        guesser = SSHDetect(device_type="autodetect", host=host, username=username,
                            password=password, port=port, conn_timeout=timeout,
                            auth_timeout=timeout, banner_timeout=timeout)
        best = guesser.autodetect()
        try:
            guesser.connection.disconnect()
        except Exception:
            pass
        return best
    except NetmikoAuthenticationException as exc:
        raise AuthError(f"{host}: authentication failed") from exc
    except Exception as exc:
        log.debug("autodetect %s failed: %s", host, exc)
        return None


# ---------------------------------------------------------------- ICMP

def ping(host: str, timeout: float = 1.5) -> float | None:
    """One system ping. Returns RTT in ms, or None if unreachable."""
    if sys.platform.startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), host]
    t0 = time.monotonic()
    try:
        rc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=timeout + 2).returncode
    except (subprocess.TimeoutExpired, OSError):
        return None
    return round((time.monotonic() - t0) * 1000, 1) if rc == 0 else None


# ---------------------------------------------------------------- SNMP

def _hl():
    import importlib
    for modname in ("pysnmp.hlapi.v3arch.asyncio", "pysnmp.hlapi.asyncio"):
        try:
            return importlib.import_module(modname)
        except ImportError:
            continue
    raise ImportError("pysnmp is not installed")


def _attr(hl, *names):
    for n in names:
        if hasattr(hl, n):
            return getattr(hl, n)
    raise AttributeError(f"pysnmp API mismatch, none of {names} found")


def _auth(hl, s: SnmpSettings):
    if s.version == "v3":
        auth_map = {"sha": "usmHMACSHAAuthProtocol", "md5": "usmHMACMD5AuthProtocol",
                    "none": "usmNoAuthProtocol"}
        priv_map = {"aes128": "usmAesCfb128Protocol", "des": "usmDESPrivProtocol",
                    "none": "usmNoPrivProtocol"}
        return hl.UsmUserData(
            s.v3_user,
            authKey=s.v3_auth_key or None,
            privKey=s.v3_priv_key or None,
            authProtocol=getattr(hl, auth_map.get(s.v3_auth_proto, "usmHMACSHAAuthProtocol")),
            privProtocol=getattr(hl, priv_map.get(s.v3_priv_proto, "usmAesCfb128Protocol")),
        )
    return hl.CommunityData(s.community, mpModel=1)  # v2c


async def _transport(hl, host: str, port: int, timeout: float, retries: int):
    if hasattr(hl.UdpTransportTarget, "create"):
        return await hl.UdpTransportTarget.create((host, port), timeout=timeout, retries=retries)
    return hl.UdpTransportTarget((host, port), timeout=timeout, retries=retries)


def _value(v) -> str:
    """Render a pysnmp value: printable text stays text, binary becomes aa:bb:cc.. hex."""
    try:
        raw = v.asOctets()
    except AttributeError:
        try:
            return str(v.prettyPrint())
        except AttributeError:
            return str(v)
    try:
        txt = raw.decode("ascii")
        if txt.isprintable():
            return txt
    except UnicodeDecodeError:
        pass
    return ":".join(f"{b:02x}" for b in raw)


def snmp_get(host: str, s: SnmpSettings, oids: list[str],
             timeout: float = 2.0, retries: int = 1) -> dict[str, str]:
    """GET a list of OIDs. Returns {oid: value}; empty dict on any failure."""
    try:
        hl = _hl()
    except ImportError:
        return {}

    async def _run():
        engine = hl.SnmpEngine()
        try:
            tt = await _transport(hl, host, s.port, timeout, retries)
            get_cmd = _attr(hl, "get_cmd", "getCmd")
            err, stat, _idx, binds = await get_cmd(
                engine, _auth(hl, s), tt, hl.ContextData(),
                *[hl.ObjectType(hl.ObjectIdentity(o)) for o in oids])
            if err or stat:
                return {}
            return {str(name): _value(val) for name, val in binds}
        finally:
            _close_engine(engine)

    try:
        return asyncio.run(_run())
    except Exception as exc:
        log.debug("snmp_get %s failed: %s", host, exc)
        return {}


def snmp_walk(host: str, s: SnmpSettings, oid: str, timeout: float = 2.0,
              retries: int = 1, max_rows: int = 5000) -> list[tuple[str, str]]:
    """WALK a subtree. Returns [(oid, value), ...]; empty list on any failure."""
    try:
        hl = _hl()
    except ImportError:
        return []

    async def _run():
        engine = hl.SnmpEngine()
        rows: list[tuple[str, str]] = []
        try:
            tt = await _transport(hl, host, s.port, timeout, retries)
            walk_cmd = _attr(hl, "walk_cmd", "walkCmd")
            async for err, stat, _idx, binds in walk_cmd(
                    engine, _auth(hl, s), tt, hl.ContextData(),
                    hl.ObjectType(hl.ObjectIdentity(oid))):
                if err or stat:
                    break
                stop = False
                for name, val in binds:
                    n = str(name)
                    if not (n == oid or n.startswith(oid + ".")):
                        stop = True
                        break
                    rows.append((n, _value(val)))
                    if len(rows) >= max_rows:
                        stop = True
                        break
                if stop:
                    break
            return rows
        finally:
            _close_engine(engine)

    try:
        return asyncio.run(_run())
    except Exception as exc:
        log.debug("snmp_walk %s %s failed: %s", host, oid, exc)
        return []


def _close_engine(engine) -> None:
    for name in ("close_dispatcher", "closeDispatcher"):
        disp = getattr(engine, "transport_dispatcher", None) or getattr(engine, "transportDispatcher", None)
        if disp is not None and hasattr(disp, name):
            try:
                getattr(disp, name)()
            except Exception:
                pass
            return
