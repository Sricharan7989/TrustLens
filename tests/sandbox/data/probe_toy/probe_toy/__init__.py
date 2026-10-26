"""Synthetic toy: checks the places a sample uses to see if it is being watched."""
import os
import socket


def look() -> None:
    for path in ("/.dockerenv", "/proc/1/cgroup", "/proc/uptime", "/proc/cpuinfo"):
        try:
            with open(path, "rb") as handle:
                handle.read(32)
        except OSError:
            pass
    socket.gethostname()
    os.cpu_count()
    os.environ.get("DISPLAY")
    os.environ.get("CI")
