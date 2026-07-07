"""JSON snapshot storage: one directory per discovery run.

runs/<run-id>/{run.json, devices.json, edges.json, findings.json}
"""
from __future__ import annotations

import datetime
import json
from pathlib import Path

from .models import (
    Device, Edge, Finding, RunMeta,
    device_from_dict, edge_from_dict, finding_from_dict, runmeta_from_dict, to_dict,
)


class StoreError(Exception):
    pass


class RunStore:
    def __init__(self, base_dir: str | Path = "runs"):
        self.base = Path(base_dir)

    @staticmethod
    def new_run_id() -> str:
        return datetime.datetime.now().strftime("%Y-%m-%dT%H-%M-%S")

    def run_dir(self, run_id: str) -> Path:
        return self.base / run_id

    def save_run(self, meta: RunMeta, devices: dict[str, Device], edges: list[Edge],
                 findings: list[Finding] | None = None) -> Path:
        d = self.run_dir(meta.run_id)
        d.mkdir(parents=True, exist_ok=True)
        self._write(d / "run.json", to_dict(meta))
        self._write(d / "devices.json", [to_dict(x) for x in devices.values()])
        self._write(d / "edges.json", [to_dict(x) for x in edges])
        if findings is not None:
            self.save_findings(meta.run_id, findings)
        return d

    def save_findings(self, run_id: str, findings: list[Finding]) -> None:
        d = self.run_dir(run_id)
        if not d.is_dir():
            raise StoreError(f"run '{run_id}' does not exist")
        self._write(d / "findings.json", [to_dict(x) for x in findings])

    def list_runs(self) -> list[str]:
        if not self.base.is_dir():
            return []
        return sorted(p.name for p in self.base.iterdir() if (p / "run.json").is_file())

    def resolve(self, ref: str = "latest") -> str:
        runs = self.list_runs()
        if not runs:
            raise StoreError(f"no runs found under '{self.base}' - run a discovery first")
        if ref in ("", "latest"):
            return runs[-1]
        if ref in runs:
            return ref
        matches = [r for r in runs if r.startswith(ref)]
        if len(matches) == 1:
            return matches[0]
        raise StoreError(f"run '{ref}' not found (or ambiguous). Available: {', '.join(runs)}")

    def load_run(self, ref: str = "latest") -> tuple[RunMeta, dict[str, Device], list[Edge]]:
        run_id = self.resolve(ref)
        d = self.run_dir(run_id)
        meta = runmeta_from_dict(self._read(d / "run.json"))
        devices = [device_from_dict(x) for x in self._read(d / "devices.json")]
        edges = [edge_from_dict(x) for x in self._read(d / "edges.json")]
        return meta, {dev.node_id: dev for dev in devices}, edges

    def load_findings(self, ref: str = "latest") -> list[Finding] | None:
        p = self.run_dir(self.resolve(ref)) / "findings.json"
        if not p.is_file():
            return None
        return [finding_from_dict(x) for x in self._read(p)]

    @staticmethod
    def _write(path: Path, data) -> None:
        path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n")

    @staticmethod
    def _read(path: Path):
        try:
            return json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise StoreError(f"cannot read {path}: {exc}") from exc
