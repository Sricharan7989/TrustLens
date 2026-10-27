"""Dev D: Localhost-only Web UI (standard library only, zero CDN assets, 100% offline)."""
from .server import create_server, run_server

__all__ = ["run_server", "create_server"]
