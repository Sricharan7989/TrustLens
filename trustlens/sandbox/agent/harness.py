"""Dev A: in-sandbox driver. Modes: import | call | startup. Writes coverage counters to FP_COV (JSON)."""
import importlib
import inspect
import json
import os
import pkgutil
import signal
import sys

mode = sys.argv[1]
roots = [r for r in os.environ.get("FP_PKG_DIRS", "").split(os.pathsep) if r]
cov = {"modules": 0, "modules_failed": [], "callables_total": 0, "callables_exercised": 0, "native": []}


def discover():
    mods = []
    for root in roots:
        base = os.path.join(root, "src") if os.path.isdir(os.path.join(root, "src")) else root
        for name in sorted(os.listdir(base)):
            full = os.path.join(base, name)
            if name in ("setup.py", "conftest.py", "tests", "test", "docs", "build") or name.startswith((".", "_")) and name != "__init__.py":
                continue
            if os.path.isdir(full) and os.path.exists(os.path.join(full, "__init__.py")):
                mods.append(name)
                for m in pkgutil.walk_packages([full], prefix=name + ".", onerror=lambda n: None):
                    mods.append(m.name)
            elif name.endswith(".py"):
                mods.append(name[:-3])
            elif name.endswith((".so", ".pyd")):
                cov["native"].append(name)
    return mods


def dummy(p):
    ann = p.annotation
    if ann in (int,):
        return 1
    if ann in (float,):
        return 1.0
    if ann in (bool,):
        return True
    if ann in (list,):
        return ["Hello World"]
    if ann in (dict,):
        return {"a": "Hello World"}
    if ann in (bytes,):
        return b"Hello World"
    return "Hello World"


class _Timeout(Exception):
    pass


def _alarm(*_a):
    raise _Timeout()


signal.signal(signal.SIGALRM, _alarm)
if mode == "startup":
    pass  # fresh interpreter only; the agent already ran from sitecustomize
else:
    for name in discover():
        try:
            signal.alarm(5)
            mod = importlib.import_module(name)
            signal.alarm(0)
            cov["modules"] += 1
        except BaseException as e:  # noqa: BLE001
            signal.alarm(0)
            cov["modules_failed"].append(f"{name}: {type(e).__name__}")
            continue
        if mode != "call":
            continue
        for n, f in inspect.getmembers(mod, callable):
            if n.startswith("_") or getattr(f, "__module__", "") != mod.__name__:
                continue
            cov["callables_total"] += 1
            try:
                sig = inspect.signature(f)
                args = [dummy(p) for p in sig.parameters.values()
                        if p.default is p.empty and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
            except (TypeError, ValueError):
                args = ["Hello World"]
            try:
                signal.alarm(3)
                f(*args)
            except BaseException:  # noqa: BLE001
                pass
            finally:
                signal.alarm(0)
            cov["callables_exercised"] += 1
with open(os.environ["FP_COV"], "a") as fh:
    fh.write(json.dumps(cov) + "\n")
