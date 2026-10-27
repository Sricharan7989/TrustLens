"""Dev A: in-sandbox tracing agent (loaded as sitecustomize). Emits raw events (schemas/raw_event.schema.json).

Layer 1 = sys.addaudithook. Env reads are wrapped because CPython has no env-read audit event.
`os.getenv`, `os.environ.get`, `in`, and bulk dumps (`.items` / `.copy` / `dict(os.environ)`) are covered.
Bulk dumps emit one `env.read` with `name: "*"`; canary keys in that dump still get their own event.
Clock variant `clock+30d` patches Python time only when libfaketime is not already loaded (`FP_CLOCK=python`).
"""
from __future__ import annotations

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
    _AGENT_DIR = os.path.dirname(os.path.realpath(__file__))
    _STDLIB = tuple({os.path.realpath(sys.base_prefix + "/lib"), "/usr/lib/python3", "/usr/lib64/python3", "/usr/local/lib/python3"})
    _CAN: dict = {}
    try:
        _CAN = json.load(open(os.environ["FP_CANARIES"], encoding="utf-8")) if os.environ.get("FP_CANARIES") else {}
    except (OSError, json.JSONDecodeError, KeyError):
        _CAN = {}
    _TOKENS = {c["token"]: c["id"] for c in _CAN.get("canaries", []) if c.get("token")}
    _FILE_CANS = [(c["where"], c["id"]) for c in _CAN.get("canaries", []) if c.get("kind") == "file"]
    _ENV_CANS = {c["where"]: c["id"] for c in _CAN.get("canaries", []) if c.get("kind") == "env"}
    _BENIGN_ENV = {
        "PYTHONPATH", "HOME", "PATH", "LANG", "LC_ALL", "LC_CTYPE", "PYTHONIOENCODING", "PYTHONHOME", "TERM",
        "PYTHONUTF8", "PYTHONDONTWRITEBYTECODE", "PYTHON_COLORS", "NO_COLOR", "FORCE_COLOR", "TMPDIR", "TEMP", "TMP",
        "PYTHONWARNINGS", "PYTHONSTARTUP", "PYTHONINSPECT", "PYTHONNOUSERSITE", "PYTHONSAFEPATH",
    }
    # Do not blanket-skip /proc: packages probe /proc/1/cgroup, /proc/uptime and
    # /proc/cpuinfo. Stdlib frames are dropped later by attribution.
    _SKIP_PREFIX = (
        "/dev/", "/sys/", "/etc/ld.so", "/etc/localtime", "/etc/mime", "/usr/lib/locale",
        "/etc/locale", "/usr/share/zoneinfo", "/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf",
    ) + _STDLIB
    _IGNORE = tuple(p for p in os.environ.get("FP_IGNORE", "").split(os.pathsep) if p)
    _SEQ = [0]
    _SKIP_FRAMES = {"os.py", "_collections_abc.py"}
    _SKIP_FROZEN = {"<frozen os>", "<frozen _collections_abc>"}

    def _load_local(name: str):
        try:
            return __import__(name)
        except ImportError:
            import importlib
            return importlib.import_module(f"trustlens.sandbox.agent.{name}")

    def _forms(token: str) -> list[str]:
        return _load_local("canarymatch").token_forms(token)

    _FORM_INDEX: list[tuple[str, str]] = []
    for _tok, _cid in _TOKENS.items():
        for _form in _forms(_tok):
            _FORM_INDEX.append((_form, _cid))

    # Libraries shipped with the sandbox interpreter itself (e.g. Ubuntu's python3-attr in
    # /usr/lib/python3/dist-packages). The package is installed under /w, never here: /usr is
    # read-only in the sandbox, so code in these folders cannot belong to the scanned package.
    _SYSTEM_LIBS = ("/usr/lib/python3/dist-packages/", "/usr/lib/python3/site-packages/",
                    "/usr/local/lib/python3/dist-packages/")

    def _is_system_lib(fn: str) -> bool:
        if fn.startswith(_SYSTEM_LIBS):
            return True
        parts = fn.split("/")
        # /usr/lib/python3.12/dist-packages/..., /usr/local/lib/python3.12/site-packages/...
        return (len(parts) > 5 and parts[1] == "usr" and parts[-1] != ""
                and any(p.startswith("python3") for p in parts[2:5])
                and any(p in ("dist-packages", "site-packages") for p in parts[3:6]))

    def _is_stdlib(fn: str) -> bool:
        if fn.startswith("<frozen") or _is_system_lib(fn):
            return True
        return fn.startswith(_STDLIB) and "site-packages" not in fn and "dist-packages" not in fn

    def _classify(fn: str) -> str | None:
        if not fn:
            return None
        if fn.startswith(_AGENT_DIR) or "/sandbox/agent/" in fn:
            return None
        if _is_stdlib(fn):
            return None
        tool_bits = ("/setuptools/", "/pkg_resources/", "/_distutils_hack/", "/pip/", "/wheel/", "/packaging/")
        if any(fn.startswith(t) for t in _TOOLS) or any(bit in fn for bit in tool_bits):
            return "toolchain"
        if any(fn.startswith(p) for p in _PKG) or not fn.startswith(("/", "<")):
            return "pkg"
        if fn.startswith("<"):
            if "pip-setuptools-caller" in fn or fn.startswith("<pip"):
                return "toolchain"
            return "pkg"
        if "site-packages" in fn or "dist-packages" in fn:
            tail = fn.split("site-packages/")[-1].split("dist-packages/")[-1]
            part = tail.split("/")[0]
            name = part.split("-")[0].split(".")[0]
            if name in {"pip", "setuptools", "pkg_resources", "wheel", "packaging", "_distutils_hack"}:
                return "toolchain"
            return "dep:" + name if name else "pkg"
        return "pkg"

    def _attrib(depth: int = 2):
        try:
            frame = sys._getframe(depth)
        except ValueError:
            return None, {}
        while frame:
            who = _classify(frame.f_code.co_filename)
            if who:
                return who, {"file": frame.f_code.co_filename, "line": frame.f_lineno}
            frame = frame.f_back
        return None, {}

    def _canary_match(*texts: object) -> list[str]:
        blob = " ".join(str(t) for t in texts if t is not None)
        if not blob:
            return []
        found = {cid for form, cid in _FORM_INDEX if form in blob}
        return sorted(found)

    def _file_canaries(path: str) -> list[str]:
        return sorted({cid for where, cid in _FILE_CANS if path.endswith("/" + where) or path.endswith(where)})

    def _emit(kind, detail, outcome="attempted", who=None, ev=None, layer="audit", cm=None):
        if getattr(_STATE, "busy", False):
            return
        _STATE.busy = True
        try:
            if who is None:
                who, ev = _attrib(3)
            if who in (None, "toolchain"):
                return
            if cm is None:
                cm = _canary_match(json.dumps(detail, default=str))
            rec = {
                "seq": _SEQ[0],
                "t": time.time(),
                "phase": os.environ.get("FP_PHASE", "import"),
                "trigger": os.environ.get("FP_TRIGGER", "import_all"),
                "profile": os.environ.get("FP_PROFILE", "dev"),
                "variant": os.environ.get("FP_VARIANT", "default"),
                "kind": kind,
                "detail": detail,
                "outcome": outcome,
                "attributed_to": who,
                "evidence": dict(ev or {}, layer=layer),
                "canary_match": cm,
            }
            _SEQ[0] += 1
            _fh.write(json.dumps(rec, default=str) + "\n")
        finally:
            _STATE.busy = False

    def _caller_env():
        frame = sys._getframe(2)
        while frame and (
            os.path.basename(frame.f_code.co_filename) in _SKIP_FRAMES
            or frame.f_code.co_filename in _SKIP_FROZEN
            or frame.f_code.co_filename.startswith(_AGENT_DIR)
        ):
            frame = frame.f_back
        if not frame:
            return None, {}
        who = _classify(frame.f_code.co_filename)
        return who, {"file": frame.f_code.co_filename, "line": frame.f_lineno}

    def _emit_env(name: str, found: bool, *, force_who=None, force_ev=None):
        who, ev = (force_who, force_ev) if force_who is not None else _caller_env()
        if who in (None, "toolchain"):
            return
        if name != "*" and (name.startswith("FP_") or name in _BENIGN_ENV):
            return
        cm = [_ENV_CANS[name]] if (name in _ENV_CANS and found) else []
        _emit("env.read", {"name": name}, "succeeded" if found else "attempted", who, ev, layer="env", cm=cm)

    def _hook(event, args):
        if getattr(_STATE, "busy", False):
            return
        try:
            if event == "open":
                path, mode, flags = args
                if not isinstance(path, (str, bytes)) or isinstance(path, int):
                    return
                path = os.fsdecode(path)
                if path == _LOG or path.endswith(".pyc") or path.startswith(_SKIP_PREFIX + _IGNORE + _TOOLS) or "/__pycache__/" in path:
                    return
                writing = isinstance(flags, int) and bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND))
                if not writing and isinstance(mode, str):
                    writing = any(ch in mode for ch in "wax+")
                who, ev = _attrib(2)
                if who in (None, "toolchain"):
                    return
                if not writing and any(path.startswith(pkg) for pkg in _PKG):
                    return
                if writing:
                    _emit("file.write", {"path": path, "mode": str(mode)}, "attempted", who, ev)
                else:
                    _STATE.busy = True
                    try:
                        exists = os.path.exists(path)
                    finally:
                        _STATE.busy = False
                    _emit(
                        "file.read",
                        {"path": path, "mode": str(mode)},
                        "succeeded" if exists else "attempted",
                        who,
                        ev,
                        cm=_file_canaries(path),
                    )
            elif event == "urllib.Request":
                url, data, headers, method = args
                who, ev = _attrib(2)
                if who in (None, "toolchain"):
                    return
                if isinstance(data, (bytes, bytearray)):
                    data_head = bytes(data[:200]).decode("utf-8", "replace")
                elif data is None:
                    data_head = ""
                else:
                    data_head = str(data)[:200]
                if isinstance(headers, dict):
                    header_s = " ".join(f"{key}: {val}" for key, val in headers.items())[:400]
                else:
                    header_s = str(headers or "")[:400]
                _emit(
                    "net.http",
                    {"url": str(url), "method": str(method), "data_head": data_head, "headers": header_s},
                    "blocked",
                    who,
                    ev,
                )
            elif event == "socket.getaddrinfo":
                who, ev = _attrib(2)
                if who not in (None, "toolchain"):
                    _emit("net.dns", {"host": str(args[0])}, "blocked", who, ev)
            elif event == "socket.connect":
                who, ev = _attrib(2)
                if who not in (None, "toolchain"):
                    dest = ":".join(str(x) for x in args[1][:2]) if isinstance(args[1], tuple) else str(args[1])
                    _emit("net.connect", {"dest": dest}, "blocked", who, ev)
            elif event in ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"):
                who, ev = _attrib(2)
                if who in (None, "toolchain"):
                    return
                if event == "subprocess.Popen" and len(args) >= 2 and isinstance(args[1], (list, tuple)):
                    argv = [str(part) for part in args[1]]
                else:
                    argv = [str(part) for part in args[:3]]
                _emit("proc.spawn", {"argv": argv, "via": event}, "attempted", who, ev)
            elif event in ("compile", "exec"):
                frame = sys._getframe(1)
                who = _classify(frame.f_code.co_filename)
                if who in (None, "toolchain"):
                    return
                if event == "compile":
                    src, fname = args[0], args[1]
                    if not str(fname).startswith("<"):
                        return
                    text = src.decode("utf-8", "replace") if isinstance(src, (bytes, bytearray)) else str(src)
                    if "pip-setuptools-caller" in text or "pip-setuptools-caller" in str(fname):
                        return
                    import hashlib
                    _emit(
                        "dyn.compile",
                        {"code_sha256": hashlib.sha256(text.encode()).hexdigest(), "decoded_snippet": text[:500], "source_kind": "compile"},
                        "succeeded",
                        who,
                        {"file": frame.f_code.co_filename, "line": frame.f_lineno},
                    )
                else:
                    code = args[0]
                    if "pip-setuptools-caller" in str(getattr(code, "co_filename", "")):
                        return
                    if str(getattr(code, "co_filename", "")).startswith("<"):
                        consts = getattr(code, "co_consts", ()) or ()
                        snippet = " ".join(item for item in consts if isinstance(item, str))[:500]
                        _emit(
                            "dyn.exec",
                            {
                                "co_name": getattr(code, "co_name", "?"),
                                "co_filename": code.co_filename,
                                "decoded_snippet": snippet,
                            },
                            "succeeded",
                            who,
                            {"file": frame.f_code.co_filename, "line": frame.f_lineno},
                        )
            elif event == "ctypes.dlopen":
                who, ev = _attrib(2)
                if who not in (None, "toolchain"):
                    _emit("native.load", {"path": str(args[0])}, "attempted", who, ev)
        except Exception:
            pass

    sys.addaudithook(_hook)

    _orig_getitem = os._Environ.__getitem__
    _orig_iter = os._Environ.__iter__

    def _getitem(self, key):
        try:
            value = _orig_getitem(self, key)
            found = True
        except KeyError:
            found = False
            raise
        finally:
            try:
                name = key.decode() if isinstance(key, bytes) else str(key)
                if getattr(_STATE, "iter_depth", 0):
                    _STATE.iter_gets = getattr(_STATE, "iter_gets", 0) + 1
                    if _STATE.iter_gets == 1:
                        _emit_env("*", True)
                    if name in _ENV_CANS:
                        _emit_env(name, found)
                elif getattr(_STATE, "suppress", 0) > 0:
                    _STATE.suppress -= 1
                    if name in _ENV_CANS:
                        _emit_env(name, found)
                else:
                    _emit_env(name, found)
            except Exception:
                pass
        return value

    def _iter(self):
        depth = getattr(_STATE, "iter_depth", 0)
        _STATE.iter_depth = depth + 1
        gets_before = getattr(_STATE, "iter_gets", 0) if depth else 0
        if depth == 0:
            _STATE.iter_gets = 0
        size = len(self._data) if hasattr(self, "_data") else 0
        try:
            yield from _orig_iter(self)
        finally:
            _STATE.iter_depth = depth
            if depth == 0 and getattr(_STATE, "iter_gets", 0) == gets_before:
                _emit_env("*", True)
                _STATE.suppress = size

    os._Environ.__getitem__ = _getitem
    os._Environ.__iter__ = _iter

    def _install_socket_wrappers() -> None:
        import socket as _socket

        def _peer(sock) -> str:
            try:
                peer = sock.getpeername()
                if isinstance(peer, tuple) and peer:
                    return ":".join(str(part) for part in peer[:2])
            except OSError:
                return ""
            return ""

        def _head(data) -> str:
            if isinstance(data, (bytes, bytearray)):
                return bytes(data[:180]).decode("utf-8", "replace")
            return str(data)[:180]

        def _wrap_send(method: str):
            orig = getattr(_socket.socket, method)

            def wrapped(self, data, *args, **kwargs):
                try:
                    dest = _peer(self)
                    if method == "sendto" and args:
                        dest = str(args[0])
                    _emit("net.send", {"dest": dest, "data_head": _head(data)}, "attempted")
                except Exception:
                    pass
                return orig(self, data, *args, **kwargs)

            setattr(_socket.socket, method, wrapped)

        for _name in ("send", "sendall", "sendto"):
            _wrap_send(_name)

        real_host = _socket.gethostname

        def _gethostname():
            try:
                _emit("env.read", {"name": "HOSTNAME", "via": "gethostname"}, "succeeded", layer="env")
            except Exception:
                pass
            return real_host()

        _socket.gethostname = _gethostname

    def _install_cpu_wrapper() -> None:
        real_cpu = os.cpu_count

        def _cpu_count():
            try:
                _emit("env.read", {"name": "NUMBER_OF_PROCESSORS", "via": "cpu_count"}, "succeeded", layer="env")
            except Exception:
                pass
            return real_cpu()

        os.cpu_count = _cpu_count

    def _install_clock() -> None:
        if os.environ.get("FP_VARIANT") != "clock+30d" or os.environ.get("FP_CLOCK") == "libfaketime":
            return
        import datetime as _dt

        shift = 30 * 24 * 3600
        real_time = time.time

        def _shifted() -> float:
            return real_time() + shift

        time.time = _shifted
        delta = _dt.timedelta(days=30)
        real_now = _dt.datetime.now
        real_utcnow = _dt.datetime.utcnow
        real_today = _dt.date.today

        def _now(tz=None):
            return real_now(tz) + delta

        def _utcnow():
            return real_utcnow() + delta

        def _today():
            return real_today() + delta

        _dt.datetime.now = _now  # type: ignore[method-assign]
        _dt.datetime.utcnow = _utcnow  # type: ignore[method-assign]
        _dt.date.today = _today  # type: ignore[method-assign]

    _install_socket_wrappers()
    _install_cpu_wrapper()
    _install_clock()
    if os.environ.get("FP_SINKHOLE") == "1":
        try:
            _STATE.busy = True
            _load_local("sinkhole").start()
        except Exception:
            pass
        finally:
            _STATE.busy = False
