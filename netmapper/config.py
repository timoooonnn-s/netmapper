"""Configuration: netmapper.toml plus credential resolution (env vars / interactive prompt).

Passwords are never stored in the config file. Resolution order:
  username: profile value -> NETMAPPER_USERNAME env -> interactive prompt
  password: env named by profile's password_env -> NETMAPPER_PASSWORD env -> getpass prompt
"""
from __future__ import annotations

import getpass
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


class ConfigError(Exception):
    pass


@dataclass
class SnmpSettings:
    version: str = "v2c"           # v2c | v3
    port: int = 161
    community: str = field(default="", repr=False)
    community_env: str = ""
    v3_user: str = ""
    v3_auth_proto: str = "sha"     # sha | md5 | none
    v3_priv_proto: str = "aes128"  # aes128 | des | none
    v3_auth_key_env: str = ""
    v3_priv_key_env: str = ""
    v3_auth_key: str = field(default="", repr=False)
    v3_priv_key: str = field(default="", repr=False)

    def resolve(self) -> None:
        if not self.community and self.community_env:
            self.community = os.environ.get(self.community_env, "")
        if not self.v3_auth_key and self.v3_auth_key_env:
            self.v3_auth_key = os.environ.get(self.v3_auth_key_env, "")
        if not self.v3_priv_key and self.v3_priv_key_env:
            self.v3_priv_key = os.environ.get(self.v3_priv_key_env, "")

    @property
    def usable(self) -> bool:
        if self.version == "v3":
            return bool(self.v3_user)
        return bool(self.community)


@dataclass
class Profile:
    name: str
    username: str = ""
    password_env: str = ""
    ssh_port: int = 22
    ssh_timeout: int = 15
    snmp: SnmpSettings | None = None
    password: str = field(default="", repr=False)

    def resolve_credentials(self, interactive: bool = True) -> None:
        if not self.username:
            self.username = os.environ.get("NETMAPPER_USERNAME", "")
        if not self.username and interactive:
            self.username = input(f"[{self.name}] username: ").strip()
        if not self.password:
            for env in (self.password_env, "NETMAPPER_PASSWORD"):
                if env and os.environ.get(env):
                    self.password = os.environ[env]
                    break
        if not self.password and interactive:
            self.password = getpass.getpass(f"[{self.name}] password for '{self.username}': ")
        if self.snmp:
            self.snmp.resolve()
        if not self.username or not self.password:
            raise ConfigError(
                f"profile '{self.name}': username/password could not be resolved "
                f"(set them interactively, via {self.password_env or 'password_env'}, "
                "or NETMAPPER_USERNAME / NETMAPPER_PASSWORD)"
            )


@dataclass
class Defaults:
    depth: int = 3
    workers: int = 10
    max_devices: int = 200
    arp_limit: int = 30
    runs_dir: str = "runs"


@dataclass
class Config:
    defaults: Defaults = field(default_factory=Defaults)
    profiles: dict[str, Profile] = field(default_factory=dict)
    seed_groups: dict[str, list[str]] = field(default_factory=dict)
    path: str = ""


def load_config(path: str | None = None) -> Config:
    cfg = Config()
    p = Path(path) if path else Path("netmapper.toml")
    if not p.exists():
        if path:
            raise ConfigError(f"config file not found: {p}")
        return cfg  # running without a config file is fine
    try:
        data = tomllib.loads(p.read_text())
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{p}: {exc}") from exc

    for k, v in data.get("defaults", {}).items():
        if k in Defaults.__dataclass_fields__:
            setattr(cfg.defaults, k, v)

    for name, pd in data.get("profiles", {}).items():
        snmp = None
        if isinstance(pd.get("snmp"), dict):
            snmp = SnmpSettings(**{
                k: v for k, v in pd["snmp"].items()
                if k in SnmpSettings.__dataclass_fields__
            })
        cfg.profiles[name] = Profile(
            name=name,
            username=pd.get("username", ""),
            password_env=pd.get("password_env", ""),
            ssh_port=int(pd.get("ssh_port", 22)),
            ssh_timeout=int(pd.get("ssh_timeout", 15)),
            snmp=snmp,
        )

    for name, sd in data.get("seeds", {}).items():
        ips = sd.get("ips", []) if isinstance(sd, dict) else sd
        cfg.seed_groups[name] = [str(i) for i in ips]

    cfg.path = str(p)
    return cfg


def get_profile(cfg: Config, name: str | None) -> Profile:
    if name:
        if name not in cfg.profiles:
            raise ConfigError(f"profile '{name}' not found (have: {', '.join(cfg.profiles) or 'none'})")
        return cfg.profiles[name]
    if len(cfg.profiles) == 1:
        return next(iter(cfg.profiles.values()))
    if not cfg.profiles:
        # No config file / profiles: build an ad-hoc profile, credentials prompted.
        return Profile(name="adhoc")
    raise ConfigError(f"multiple profiles defined, pick one with --profile ({', '.join(cfg.profiles)})")


def resolve_seeds(cfg: Config, seeds_arg: str) -> list[str]:
    """Parse '10.0.0.1,@core,10.0.0.9' into a deduplicated IP list."""
    out: list[str] = []
    for item in (seeds_arg or "").split(","):
        item = item.strip()
        if not item:
            continue
        if item.startswith("@"):
            group = cfg.seed_groups.get(item[1:])
            if group is None:
                raise ConfigError(f"seed group '{item[1:]}' not found in config")
            out.extend(group)
        else:
            out.append(item)
    seen: set[str] = set()
    return [s for s in out if not (s in seen or seen.add(s))]
