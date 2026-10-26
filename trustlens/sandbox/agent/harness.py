"""Dev A: in-sandbox driver. Modes: import | call | startup | cli.

Writes coverage counters to FP_COV (JSON). Call mode tries three argument sets
(typed dummies, strings, None), instantiates classes, runs public methods, and
executes modules that contain `if __name__ == "__main__"` via runpy.
"""
from __future__ import annotations

import importlib
import inspect
import json
import os
import pkgutil
import runpy
import signal
import sys

mode = sys.argv[1] if len(sys.argv) > 1 else "import"
roots = [r for r in os.environ.get("FP_PKG_DIRS", "").split(os.pathsep) if r]
cov = {"modules": 0, "modules_failed": [], "callables_total": 0, "callables_exercised": 0, "native": []}


def discover() -> list[str]:
    mods: list[str] = []
    seen: set[str] = set()
    for root in roots:
        base = os.path.join(root, "src") if os.path.isdir(os.path.join(root, "src")) else root
        if not os.path.isdir(base):
            continue
        for name in sorted(os.listdir(base)):
            if name.endswith((".dist-info", ".egg-info", ".pth")) or name in {"bin", "__pycache__"}:
                continue
            full = os.path.join(base, name)
            if name in ("setup.py", "conftest.py", "tests", "test", "docs", "build") or (
                name.startswith((".", "_")) and name != "__init__.py"
            ):
                continue
            found: list[str] = []
            if os.path.isdir(full) and os.path.exists(os.path.join(full, "__init__.py")):
                found.append(name)
                for mod in pkgutil.walk_packages([full], prefix=name + ".", onerror=lambda n: None):
                    found.append(mod.name)
            elif name.endswith(".py"):
                found.append(name[:-3])
            elif name.endswith((".so", ".pyd")):
                cov["native"].append(name)
            for item in found:
                if item not in seen:
                    seen.add(item)
                    mods.append(item)
    return mods


def _dummy(param, style: str):
    if style == "str":
        return "Hello World"
    if style == "none":
        return None
    ann = param.annotation
    origin = getattr(ann, "__origin__", None)
    if ann in (int,) or origin is int:
        return 1
    if ann in (float,) or origin is float:
        return 1.0
    if ann in (bool,) or origin is bool:
        return True
    if ann in (list, tuple) or origin in (list, tuple):
        return ["Hello World"]
    if ann in (dict,) or origin is dict:
        return {"a": "Hello World"}
    if ann in (bytes, bytearray) or origin in (bytes, bytearray):
        return b"Hello World"
    if ann in (type(None),):
        return None
    return "Hello World"


def _arg_sets(func):
    try:
        sig = inspect.signature(func)
        required = [
            p for p in sig.parameters.values()
            if p.default is p.empty and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
        ]
    except (TypeError, ValueError):
        return [["Hello World"], ["Hello World"], [None]]
    return [[_dummy(p, style) for p in required] for style in ("typed", "str", "none")]


class _Timeout(Exception):
    pass


def _alarm(*_args):
    raise _Timeout()


def _invoke(func, args) -> None:
    signal.alarm(3)
    try:
        func(*args)
    finally:
        signal.alarm(0)


def exercise(func) -> None:
    cov["callables_total"] += 1
    sets = _arg_sets(func)
    # Identical sets (no required args) still count as one attempt, retried only when they differ.
    tried: list = []
    for args in sets:
        if args in tried:
            continue
        tried.append(args)
        try:
            _invoke(func, args)
            break
        except _Timeout:
            break
        except TypeError:
            continue
        except BaseException:
            break
    cov["callables_exercised"] += 1


def exercise_class(cls) -> None:
    cov["callables_total"] += 1
    inst = None
    tried: list = []
    for args in _arg_sets(cls):
        if args in tried:
            continue
        tried.append(args)
        try:
            signal.alarm(3)
            inst = cls(*args)
            break
        except _Timeout:
            break
        except TypeError:
            continue
        except BaseException:
            break
        finally:
            signal.alarm(0)
    cov["callables_exercised"] += 1
    if inst is None:
        return
    for name, member in inspect.getmembers(inst, callable):
        if name.startswith("_"):
            continue
        func = getattr(member, "__func__", member)
        if getattr(func, "__module__", "") not in {cls.__module__, getattr(inst, "__module__", "")}:
            continue
        exercise(member)


def _maybe_main(mod) -> None:
    """Run a module as ``__main__``.

    ``runpy.run_module`` works for plain modules and for packages that ship
    ``__main__.py``. It refuses a package whose guard lives in ``__init__.py``,
    which is re-executed here with ``__name__`` set so the guard actually runs.
    """
    try:
        source = inspect.getsource(mod)
    except (OSError, TypeError):
        source = ""
    has_guard = "__main__" in source and "__name__" in source
    is_pkg = getattr(mod, "__path__", None) is not None
    main_py = False
    if is_pkg and mod.__path__:
        main_py = os.path.isfile(os.path.join(mod.__path__[0], "__main__.py"))
    if not has_guard and not main_py:
        return
    cov["callables_total"] += 1
    try:
        signal.alarm(3)
        if (not is_pkg) or main_py:
            runpy.run_module(mod.__name__, run_name="__main__")
        else:
            filename = inspect.getfile(mod)
            code = compile(source, filename, "exec")
            exec(code, {"__name__": "__main__", "__file__": filename, "__package__": mod.__package__})  # noqa: S102
    except BaseException:
        pass
    finally:
        signal.alarm(0)
    cov["callables_exercised"] += 1


signal.signal(signal.SIGALRM, _alarm)

if mode == "startup":
    pass
elif mode == "cli":
    spec = sys.argv[2]
    extra = sys.argv[3:]
    mod_name, func_name = spec.split(":", 1)
    sys.argv = [func_name, *extra]
    try:
        signal.alarm(5)
        mod = importlib.import_module(mod_name)
        func = getattr(mod, func_name)
        cov["callables_total"] += 1
        func()
        cov["callables_exercised"] += 1
        cov["modules"] += 1
    except BaseException as exc:  # noqa: BLE001
        cov["modules_failed"].append(f"{spec}: {type(exc).__name__}")
        if cov["callables_total"]:
            cov["callables_exercised"] += 1
    finally:
        signal.alarm(0)
else:
    for name in discover():
        try:
            signal.alarm(5)
            mod = importlib.import_module(name)
            signal.alarm(0)
            cov["modules"] += 1
        except BaseException as exc:  # noqa: BLE001
            signal.alarm(0)
            cov["modules_failed"].append(f"{name}: {type(exc).__name__}")
            continue
        if mode != "call":
            continue
        for fname, func in inspect.getmembers(mod, callable):
            if fname.startswith("_") or inspect.isclass(func) or getattr(func, "__module__", "") != mod.__name__:
                continue
            exercise(func)
        for cname, cls in inspect.getmembers(mod, inspect.isclass):
            if cname.startswith("_") or getattr(cls, "__module__", "") != mod.__name__:
                continue
            exercise_class(cls)
        _maybe_main(mod)

with open(os.environ["FP_COV"], "a", encoding="utf-8") as fh:
    fh.write(json.dumps(cov) + "\n")
