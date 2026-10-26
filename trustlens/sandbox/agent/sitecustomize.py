"""Dev A: in-sandbox tracing agent (loaded as sitecustomize). Emits raw events (schemas/raw_event.schema.json).

Layer 1 = sys.addaudithook (+ os.environ wrapper because CPython has no env-read audit event).
Env vars (set by live_probe): FP_LOG FP_PHASE FP_TRIGGER FP_PROFILE FP_VARIANT FP_PKG_DIRS FP_CANARIES FP_TOOL_DIRS
v0 limits (Dev A task list improves these): no chain-load of a package sitecustomize, no strace merge, no clock patch.
"""
import json
import os
import sys
import threading
import time

_LOG = os.environ.get("FP_LOG")
if _LOG:
    _fh = open(_LOG, "a", buffering=1)
    _STATE = threading.local()
    _PKG = tuple(p for p in os.environ.get("FP_PKG_DIRS", "").split(os.pathsep) if p)
    _TOOLS = tuple(p for p in os.environ.get("FP_TOOL_DIRS", "").split(os.pathsep) if p)
    _STDLIB = tuple({os.path.realpath(sys.base_prefix + "/lib"), "/usr/lib/python3", "/usr/lib64/python3", "/usr/local/lib/python3"})
    _CAN = {}
    try:
        _CAN = json.load(open(os.environ.get("FP_CANARIES", ""))) if os.environ.get("FP_CANARIES") else {}
    except Exception:  # noqa: BLE001
        pass
    _TOKENS = {c["token"]: c["id"] for c in _CAN.get("canaries", []) if c.get("token")}
    _FILE_CANS = [(c["where"], c["id"]) for c in _CAN.get("canaries", []) if c["kind"] == "file"]
    _ENV_CANS = {c["where"]: c["id"] for c in _CAN.get("canaries", []) if c["kind"] == "env"}
    _BENIGN_ENV = {"PYTHONPATH", "HOME", "PATH", "LANG", "LC_ALL", "LC_CTYPE", "PYTHONIOENCODING", "PYTHONHOME", "TERM",
                   "PYTHONUTF8", "PYTHONDONTWRITEBYTECODE", "PYTHON_COLORS", "NO_COLOR", "FORCE_COLOR", "TMPDIR", "TEMP", "TMP",
                   "PYTHONWARNINGS", "PYTHONSTARTUP", "PYTHONINSPECT", "PYTHONNOUSERSITE", "PYTHONSAFEPATH"}
    _SKIP_PREFIX = ("/proc/self", "/proc/", "/dev/", "/sys/", "/etc/ld.so", "/etc/localtime", "/etc/mime", "/usr/lib/locale",
                    "/etc/locale", "/usr/share/zoneinfo") + _STDLIB
    _IGNORE = tuple(p for p in os.environ.get("FP_IGNORE", "").split(os.pathsep) if p)
    _SEQ = [0]

    def _is_stdlib(fn):
        return fn.startswith("<frozen") or (fn.startswith(_STDLIB) and "site-packages" not in fn and "dist-packages" not in fn)

    def _classify(fn):
        if fn.startswith(__file__.rsplit("/", 1)[0]):
            return None  # agent itself
        if _is_stdlib(fn):
            return None
        if any(fn.startswith(t) for t in _TOOLS) or "/setuptools/" in fn or "/pkg_resources/" in fn or "/_distutils_hack/" in fn or "/pip/" in fn:
            return "toolchain"
        if any(fn.startswith(p) for p in _PKG) or not fn.startswith(("/", "<")):
            return "pkg"
        if fn.startswith("<"):
            return "pkg" if _PKG else "unknown"
        if "site-packages" in fn or "dist-packages" in fn:
            part = fn.split("site-packages/")[-1].split("/")[0]
            return "dep:" + part.split(".")[0]
        return "unknown"

    def _attrib(depth=2):
        f = sys._getframe(depth)
        while f:
            who = _classify(f.f_code.co_filename)
            if who:
                return who, {"file": f.f_code.co_filename, "line": f.f_lineno}
            f = f.f_back
        return "unknown", {}

    def _canary_match(*texts):
        s = " ".join(str(t) for t in texts if t is not None)
        return sorted({cid for tok, cid in _TOKENS.items() if tok in s})

    def _emit(kind, detail, outcome="attempted", who=None, ev=None, layer="audit", cm=None):
        if getattr(_STATE, "busy", False):
            return
        _STATE.busy = True
        try:
            if who is None:
                who, ev = _attrib(3)
            rec = {"seq": _SEQ[0], "t": time.time(), "phase": os.environ.get("FP_PHASE", "import"),
                   "trigger": os.environ.get("FP_TRIGGER", "import_all"), "profile": os.environ.get("FP_PROFILE", "dev"),
                   "variant": os.environ.get("FP_VARIANT", "default"), "kind": kind, "detail": detail, "outcome": outcome,
                   "attributed_to": who, "evidence": dict(ev or {}, layer=layer),
                   "canary_match": cm if cm is not None else _canary_match(json.dumps(detail, default=str))}
            _SEQ[0] += 1
            _fh.write(json.dumps(rec, default=str) + "\n")
        finally:
            _STATE.busy = False

    def _hook(event, args):
        if getattr(_STATE, "busy", False):
            return
        try:
            if event == "open":
                p, mode, flags = args
                if not isinstance(p, (str, bytes)) or isinstance(p, int):
                    return
                p = os.fsdecode(p)
                if p == _LOG or p.endswith(".pyc") or p.startswith(_SKIP_PREFIX + _IGNORE + _TOOLS) or "/__pycache__/" in p:
                    return
                w = isinstance(flags, int) and bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND))
                if not w and isinstance(mode, str):
                    w = any(c in mode for c in "wax+")
                who, ev = _attrib(2)
                if who in (None, "toolchain"):
                    return
                if not w and p.startswith(_PKG):
                    return  # package reading its own source/data files
                if w:
                    _emit("file.write", {"path": p, "mode": str(mode)}, "attempted", who, ev)
                else:
                    _STATE.busy = True
                    try:
                        ok = os.path.exists(p)
                    finally:
                        _STATE.busy = False
                    cm = [cid for where, cid in _FILE_CANS if p.endswith("/" + where) or p.endswith(where)]
                    _emit("file.read", {"path": p, "mode": str(mode)}, "succeeded" if ok else "attempted", who, ev, cm=cm)
            elif event == "urllib.Request":
                url, data, headers, method = args
                who, ev = _attrib(2)
                if who != "toolchain":
                    _emit("net.http", {"url": str(url), "method": str(method), "data_head": str(data)[:200]}, "blocked", who, ev)
            elif event == "socket.getaddrinfo":
                who, ev = _attrib(2)
                if who != "toolchain":
                    _emit("net.dns", {"host": str(args[0])}, "blocked", who, ev)
            elif event == "socket.connect":
                who, ev = _attrib(2)
                if who != "toolchain":
                    _emit("net.connect", {"dest": ":".join(str(x) for x in args[1][:2]) if isinstance(args[1], tuple) else str(args[1])}, "blocked", who, ev)
            elif event in ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"):
                who, ev = _attrib(2)
                if who != "toolchain":
                    _emit("proc.spawn", {"argv": [str(a) for a in args[:2]], "via": event}, "attempted", who, ev)
            elif event in ("compile", "exec"):
                f = sys._getframe(1)
                if _classify(f.f_code.co_filename) in (None, "toolchain"):
                    return
                if event == "compile":
                    src, fname = args[0], args[1]
                    if not str(fname).startswith("<"):
                        return
                    text = src.decode("utf-8", "replace") if isinstance(src, (bytes, bytearray)) else str(src)
                    import hashlib
                    _emit("dyn.compile", {"code_sha256": hashlib.sha256(text.encode()).hexdigest(), "decoded_snippet": text[:500], "source_kind": "compile"},
                          "succeeded", "pkg", {"file": f.f_code.co_filename, "line": f.f_lineno})
                else:
                    co = args[0]
                    if str(getattr(co, "co_filename", "")).startswith("<"):
                        _emit("dyn.exec", {"co_name": getattr(co, "co_name", "?"), "co_filename": co.co_filename}, "succeeded", "pkg",
                              {"file": f.f_code.co_filename, "line": f.f_lineno})
            elif event == "ctypes.dlopen":
                _emit("native.load", {"lib": str(args[0])}, "attempted")
        except Exception:  # noqa: BLE001  tracing must never crash the package under test
            pass

    sys.addaudithook(_hook)

    _orig_getitem = os._Environ.__getitem__

    def _getitem(self, key):
        found = True
        try:
            return _orig_getitem(self, key)
        except KeyError:
            found = False
            raise
        finally:
            try:
                k = key.decode() if isinstance(key, bytes) else str(key)
                if not k.startswith("FP_") and k not in _BENIGN_ENV:
                    f = sys._getframe(1)
                    while f and (f.f_code.co_filename.endswith(("/os.py", "/_collections_abc.py")) or f.f_code.co_filename in ("<frozen os>", "<frozen _collections_abc>")):
                        f = f.f_back  # skip Mapping.get/__contains__ wrappers
                    who = _classify(f.f_code.co_filename) if f else None
                    ev = {"file": f.f_code.co_filename, "line": f.f_lineno} if f else {}
                    if who not in (None, "toolchain"):
                        _emit("env.read", {"name": k}, "succeeded" if found else "attempted", who, ev,
                              cm=[_ENV_CANS[k]] if (k in _ENV_CANS and found) else [])
            except Exception:  # noqa: BLE001
                pass

    os._Environ.__getitem__ = _getitem
