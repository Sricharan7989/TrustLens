"""Dev C: baseline adapters.

Each exposes `run(pkg_dir, timeout_s)` -> `{available, flagged, rules, runtime_s, error}`.
CLI subprocess calls only (licences: GuardDog Apache-2.0, PipCanary MIT, Packj AGPL-3.0 CLI-only).
"""
from __future__ import annotations

from eval.baselines import guarddog, packj, pipcanary

__all__ = ["guarddog", "packj", "pipcanary"]
