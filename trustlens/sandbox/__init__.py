"""Dev A package: sandbox + tracing. Public API is frozen (docs/CONTRACTS.md section 2)."""
from .env_check import check_env
from .runner import DEFAULT_TRIGGERS, run_package

__all__ = ["run_package", "check_env", "DEFAULT_TRIGGERS"]
