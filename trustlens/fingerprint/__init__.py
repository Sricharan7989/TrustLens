"""Dev B: raw events -> normalized ordered fingerprint. Public API frozen (docs/CONTRACTS.md 3)."""
from .normalize import build_fingerprint
from .static_signals import collect_static_signals

__all__ = ["build_fingerprint", "collect_static_signals"]
