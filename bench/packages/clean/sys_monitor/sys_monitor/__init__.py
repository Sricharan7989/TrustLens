import os
import platform


def get_system_summary() -> dict:
    return {
        "os": platform.system(),
        "release": platform.release(),
        "arch": platform.machine(),
        "cpus": os.cpu_count() or 1,
    }
