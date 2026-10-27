import ctypes
import math


def fast_sin(x: float) -> float:
    try:
        libc = ctypes.CDLL(None)
        if hasattr(libc, "sin"):
            libc.sin.restype = ctypes.c_double
            libc.sin.argtypes = [ctypes.c_double]
            return float(libc.sin(x))
    except Exception:
        pass
    return math.sin(x)
