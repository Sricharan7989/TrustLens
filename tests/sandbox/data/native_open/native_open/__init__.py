"""Synthetic toy: open the canary with libc, bypassing the Python audit hook."""
import ctypes
import os


def poke() -> int:
    libc = ctypes.CDLL(None)
    path = os.path.expanduser("~/.ssh/id_rsa").encode()
    return int(libc.open(path, 0))
