"""Dev B: raw events -> fingerprint (capability-tagged, ordered, attributed, noise-filtered)."""
from __future__ import annotations

import copy
import fnmatch
import re
from pathlib import Path

import yaml

from trustlens.contracts import ROOT, iter_jsonl

SENSITIVE_PATH = re.compile(
    r"(\.ssh/|(?<![A-Za-z0-9])id_rsa|\.aws/|\.npmrc|\.pypirc|\.git-credentials|\.netrc|\.kube/|\.docker/config|\.config/gcloud|\.azure/|"
    r"\.mozilla/|\.config/google-chrome|Library/Application Support|/etc/shadow|/etc/passwd|\.gnupg/|\.bash_history)",
    re.I,
)
PERSIST_PATH = re.compile(
    r"(\.bashrc|\.bash_profile|\.profile|\.zshrc|\.bash_login|\.zprofile|"
    r"crontab|/cron\b|/cron\.|/var/spool/cron|"
    r"\.config/autostart|\.config/systemd|systemd/user|"
    r"authorized_keys|\.ssh/authorized_keys|/etc/init\.d|rc\.local|\.git/hooks)"
)
SECRET_ENV = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AWS_|GITHUB_|GITLAB_|NPM_|PYPI_|SSH_)", re.I)
# Decoded snippets: rejoin split literals, then match sensitive paths and real env reads.
# A bare all-caps token (TOKEN = None, for KEY, help='Set API_KEY') is not a secret read.
_STR_LIT = r"""(?:'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")"""
_LITERAL_JOIN_RE = re.compile(rf"(?P<left>{_STR_LIT})\s*(?P<op>[+/])\s*(?P<right>{_STR_LIT})")
# Implicit concat: '/etc/' 'passwd'. Whitespace only, so commas between args stay put.
_IMPLICIT_CONCAT_RE = re.compile(rf"(?P<left>{_STR_LIT})\s+(?P<right>{_STR_LIT})")
_OS_PATH_JOIN_RE = re.compile(
    rf"""os\.path\.join\s*\(\s*(?P<left>{_STR_LIT})\s*,\s*(?P<right>{_STR_LIT})"""
)
_GETATTR_ENVIRON_RE = re.compile(r"""getattr\s*\(\s*os\s*,\s*(['"])environ\1\s*\)""")
_ENV_COPY_RE = re.compile(r"""os\.environ\s*\.\s*copy\s*\(\s*\)""")
_DICT_ENVIRON_RE = re.compile(r"""dict\s*\(\s*os\.environ\s*\)""")
# Optional f/r/b (or fr/rf/rb/br) prefix so os.environ[f'NAME'] still yields NAME.
_STR_PREFIX = r"""(?:[fFrRbB]{1,2})?"""
_ENV_LOOKUP_RE = re.compile(
    rf"""os\.environ\s*\[\s*{_STR_PREFIX}(['"])(?P<idx>[^'"]+)\1"""
    rf"""|os\.environ\.get\s*\(\s*{_STR_PREFIX}(['"])(?P<get>[^'"]+)\3"""
    rf"""|os\.getenv\s*\(\s*{_STR_PREFIX}(['"])(?P<getenv>[^'"]+)\5"""
)
# Names that are secrets even when they do not contain _SECRET or end in _TOKEN.
_CURATED_SECRET_ENV = frozenset({
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GH_ENTERPRISE_TOKEN",
    "GITLAB_TOKEN",
    "GITLAB_PRIVATE_TOKEN",
    "NPM_TOKEN",
    "NODE_AUTH_TOKEN",
    "PYPI_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_CREDENTIALS",
    "AZURE_CLIENT_SECRET",
    "ARM_CLIENT_SECRET",
    "HF_TOKEN",
    "HUGGING_FACE_HUB_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "STRIPE_API_KEY",
    "SENDGRID_API_KEY",
    "SLACK_BOT_TOKEN",
    "SLACK_TOKEN",
    "TWILIO_AUTH_TOKEN",
    "DOCKER_PASSWORD",
    "PYPI_PASSWORD",
    "TWINE_PASSWORD",
    "SECRET_KEY",
    "API_KEY",
    "API_TOKEN",
    "ACCESS_TOKEN",
    "AUTH_TOKEN",
    "SESSION_TOKEN",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
})
# Looked up often, but not credentials. Never treat these as env secrets.
_NON_SECRET_ENV = frozenset({
    "SSH_AUTH_SOCK",
    "AWS_DEFAULT_REGION",
    "AWS_REGION",
    "AWS_DEFAULT_OUTPUT",
    "AWS_PROFILE",
    "AWS_ACCOUNT_ID",
    "AWS_SDK_LOAD_CONFIG",
})
PROBE_ENV = {
    "CI", "GITHUB_ACTIONS", "GITLAB_CI", "TRAVIS", "JENKINS_URL",
    "BUILDKITE", "CIRCLECI", "CONTAINER", "KUBERNETES_SERVICE_HOST",
    "HOSTNAME", "NUMBER_OF_PROCESSORS"
}
PROBE_PATH = ("/.dockerenv", "/proc/1/cgroup", "/proc/uptime", "/proc/self/cgroup", "/proc/cpuinfo")
SAFE_WRITE = re.compile(r"^(/tmp/|/var/tmp/|/w/site/|/pkg/|/w/[^/]+\.egg-info|~/\.cache/|.*/site-packages/)")


def _quote_bodies(left: str, right: str, sep: str) -> str:
    quote = left[0]
    return quote + left[1:-1] + sep + right[1:-1] + quote


def _join_literal_match(match: re.Match[str]) -> str:
    sep = "/" if match.group("op") == "/" else ""
    return _quote_bodies(match.group("left"), match.group("right"), sep)


def _implicit_concat_match(match: re.Match[str]) -> str:
    return _quote_bodies(match.group("left"), match.group("right"), "")


def _path_join_match(match: re.Match[str]) -> str:
    left, right = match.group("left"), match.group("right")
    lbody, rbody = left[1:-1], right[1:-1]
    if lbody.endswith("/"):
        joined = lbody + rbody.lstrip("/")
    elif rbody.startswith("/"):
        joined = lbody.rstrip("/") + rbody
    else:
        joined = lbody + "/" + rbody
    return left[0] + joined + left[0]


_DUNDER_IMPORT_OS_RE = re.compile(r"""__import__\s*\(\s*(['"])os\1\s*\)\s*\.""")
_IMPORT_OS_AS_RE = re.compile(r"""\bimport\s+(?:[\w.]+\s*(?:as\s+\w+)?\s*,\s*)*os\s+as\s+(?P<alias>\w+)""")
_FROM_OS_IMPORT_RE = re.compile(
    r"""\bfrom\s+os\s+import\s+(?:\((?P<paren>[\w\s,]+)\)|(?P<names>[\w \t,]+))"""
)


def _canonicalize_env_reads(text: str) -> str:
    """Turn aliased environ reads into os.environ / os.getenv so the lookup regex can see them.

    Covers `import os as o`, `from os import environ as e, getenv as g`, `__import__('os')`,
    `getattr(os, 'environ')`, `os.environ.copy()` and `dict(os.environ)`.
    """
    text = _canonicalize_os_aliases(text)
    text = _ENV_COPY_RE.sub("os.environ", text)
    return _DICT_ENVIRON_RE.sub("os.environ", text)


def _canonicalize_os_aliases(text: str) -> str:
    """Rewrite aliased `os` / `environ` / `getenv` spellings to `os.environ` / `os.getenv`."""
    text = _DUNDER_IMPORT_OS_RE.sub("os.", text)
    text = _GETATTR_ENVIRON_RE.sub("os.environ", text)
    for match in _IMPORT_OS_AS_RE.finditer(text):
        alias = re.escape(match.group("alias"))
        text = re.sub(rf"(?<![\w.]){alias}\s*\.\s*(environ|getenv)\b", r"os.\1", text)
    for match in _FROM_OS_IMPORT_RE.finditer(text):
        for part in (match.group("paren") or match.group("names") or "").split(","):
            bits = part.split()
            if not bits or bits[0] not in ("environ", "getenv"):
                continue
            name = bits[2] if len(bits) == 3 and bits[1] == "as" else bits[0]
            if bits[0] == "environ":
                text = re.sub(rf"(?<![\w.]){re.escape(name)}\s*(\[|\.get\s*\()", r"os.environ\1", text)
            else:
                text = re.sub(rf"(?<![\w.]){re.escape(name)}\s*\(", "os.getenv(", text)
    return text


def normalize_decoded_snippet(snippet: str) -> str:
    """Reassemble split string literals so denylist markers are contiguous."""
    text = _canonicalize_env_reads(snippet)
    for _ in range(32):
        updated = _LITERAL_JOIN_RE.sub(_join_literal_match, text)
        updated = _IMPLICIT_CONCAT_RE.sub(_implicit_concat_match, updated)
        updated = _OS_PATH_JOIN_RE.sub(_path_join_match, updated)
        if updated == text:
            return text
        text = updated
    return text


_SECRET_NAME_PART_RE = re.compile(r"(?:^|_)(?:SECRET|PASSWORD|PASSWD|PASSPHRASE|CREDENTIALS?|PRIVATE_KEY|ACCESS_KEY|API_KEY)(?:_|$)")


def _env_name_is_secret(name: str) -> bool:
    """True for a curated secret name, a secret word as a whole name part, or a *_TOKEN / *_KEY suffix.

    Whole name parts only: DB_PASSWORD, SSH_PRIVATE_KEY and SERVICE_CREDENTIALS are secrets;
    MY_TOKEN_COUNT and PRIMARY_KEYBOARD are not.
    """
    upper = name.strip().upper()
    if not upper or upper in PROBE_ENV or upper in _NON_SECRET_ENV:
        return False
    if upper in _CURATED_SECRET_ENV:
        return True
    if _SECRET_NAME_PART_RE.search(upper):
        return True
    return upper.endswith("_TOKEN") or upper.endswith("_KEY")


def snippet_mentions_env_secret(snippet: str) -> bool:
    """True when a decoded snippet reads a real secret env name, not a loose token."""
    normalized = normalize_decoded_snippet(snippet)
    for match in _ENV_LOOKUP_RE.finditer(normalized):
        name = match.group("idx") or match.group("get") or match.group("getenv") or ""
        if _env_name_is_secret(name):
            return True
    return "env" in _ast_secret_kinds(snippet)


# /proc/<pid>/environ holds the whole environment (every secret) of a process.
PROC_ENVIRON_PATH = re.compile(r"^/proc/(?:self|thread-self|\d+)/environ$")
_PROC_ENVIRON_TEXT_RE = re.compile(r"/proc/(?:self|thread-self|\d+|\{[^{}]*\}|\x00)/environ\b")
# A copy or dump of the whole environment. In the sandbox that always includes the canary secrets.
_BULK_ENV_RE = re.compile(
    r"""dict\s*\(\s*os\.environb?\b"""
    r"""|os\.environb?\s*\.\s*(?:copy|items|values)\s*\("""
    r"""|\*\*\s*os\.environb?\b"""
    r"""|\b(?:str|repr|json\.dumps|pickle\.dumps|marshal\.dumps)\s*\(\s*os\.environb?\b"""
    r"""|os\.environb?\s*\.\s*_data\b"""
)
# Credential-provider prefixes. A name built at runtime from one of them (f'GITHUB_{x}') is treated as a secret.
_PROVIDER_PREFIX_RE = re.compile(
    r"^(?:AWS|GITHUB|GH|GITLAB|NPM|PYPI|TWINE|AZURE|ARM|GOOGLE|GCP|DOCKER|SLACK|STRIPE|OPENAI|ANTHROPIC|HF|HUGGING_FACE)_\x00"
)
_HOLE = "\x00"  # stands for a part of a string that cannot be resolved statically
_AST_MAX_CHARS = 20000


def snippet_has_denylisted_secret(snippet: str) -> bool:
    """True when a decoded snippet touches a sensitive path or reads a real secret env name.

    Regex checks on the joined text first, then a static evaluation of the code (`_ast_secret_kinds`)
    that resolves f-strings, `+`, `%`, `.format`, `.join`, `os.path.join`, `Path /` and simple
    `name = '...'` constants, so names and paths built at runtime are still seen.
    """
    normalized = normalize_decoded_snippet(snippet)
    if SENSITIVE_PATH.search(normalized) or _PROC_ENVIRON_TEXT_RE.search(normalized):
        return True
    aliased = _canonicalize_os_aliases(snippet)
    if _BULK_ENV_RE.search(aliased) or _env_loop_dump(aliased):
        return True
    if snippet_mentions_env_secret(normalized):
        return True
    return bool(_ast_secret_kinds(snippet))


_ENV_LOOP_RE = re.compile(r"\bfor\s+(?P<var>\w+)(?:\s*,\s*\w+)?\s+in\s+os\.environ\b(?:\s*\.\s*keys\s*\(\s*\))?\s*:")


def _env_loop_dump(text: str) -> bool:
    """`for k in os.environ: ... os.environ[k]` (regex fallback for snippets that do not parse)."""
    for match in _ENV_LOOP_RE.finditer(text):
        var = re.escape(match.group("var"))
        if re.search(rf"os\.environ\s*(?:\[\s*{var}\s*\]|\.get\s*\(\s*{var}\b)|os\.getenv\s*\(\s*{var}\b", text[match.end():]):
            return True
    return False


def _ast_secret_kinds(snippet: str) -> set[str]:
    """Statically evaluate a snippet; return {'env', 'path', 'bulk'} for the secret accesses found.

    Never executes anything. Returns an empty set when the snippet does not parse.
    """
    if len(snippet) > _AST_MAX_CHARS:
        return set()
    import ast
    import textwrap

    try:
        tree = ast.parse(textwrap.dedent(snippet))
    except (SyntaxError, ValueError, RecursionError):
        return set()
    return _SecretScan(tree).kinds


class _SecretScan:
    """One pass to learn aliases and string constants, one pass to find secret reads."""

    def __init__(self, tree) -> None:
        import ast

        self.ast = ast
        self.os_names = {"os"}
        self.environ_names: set[str] = set()
        self.getenv_names: set[str] = set()
        self.consts: dict[str, str] = {}
        self.kinds: set[str] = set()
        for node in ast.walk(tree):
            self._learn(node)
        for node in ast.walk(tree):
            self._check(node)

    # pass 1 ---------------------------------------------------------------
    def _learn(self, node) -> None:
        ast = self.ast
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "os":
                    self.os_names.add(alias.asname or "os")
        elif isinstance(node, ast.ImportFrom) and node.module == "os":
            for alias in node.names:
                if alias.name in ("environ", "environb"):
                    self.environ_names.add(alias.asname or alias.name)
                elif alias.name in ("getenv", "getenvb"):
                    self.getenv_names.add(alias.asname or alias.name)
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if self._is_environ(node.value):
                self.environ_names.add(name)
            elif isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                self.consts.setdefault(name, node.value.value)

    # helpers --------------------------------------------------------------
    def _is_os(self, node) -> bool:
        ast = self.ast
        if isinstance(node, ast.Name):
            return node.id in self.os_names
        return (
            isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "__import__"
            and len(node.args) == 1 and isinstance(node.args[0], ast.Constant) and node.args[0].value == "os"
        )

    def _is_environ(self, node) -> bool:
        ast = self.ast
        if isinstance(node, ast.Name):
            return node.id in self.environ_names
        if isinstance(node, ast.Attribute):
            return node.attr in ("environ", "environb") and self._is_os(node.value)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr" and len(node.args) >= 2:
            return self._is_os(node.args[0]) and isinstance(node.args[1], ast.Constant) and node.args[1].value in ("environ", "environb")
        return False

    def _env_lookup_arg(self, node):
        """The name expression of os.environ[x] / os.environ.get(x) / os.getenv(x), else None."""
        ast = self.ast
        if isinstance(node, ast.Subscript) and self._is_environ(node.value):
            return node.slice
        if isinstance(node, ast.Call) and node.args:
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in ("get", "pop") and self._is_environ(func.value):
                return node.args[0]
            if isinstance(func, ast.Attribute) and func.attr in ("getenv", "getenvb") and self._is_os(func.value):
                return node.args[0]
            if isinstance(func, ast.Name) and func.id in self.getenv_names:
                return node.args[0]
        return None

    def _call_name(self, func) -> str:
        """Dotted name of a call target, e.g. 'os.path.join' or 'Path.home' ('' when not simple)."""
        ast = self.ast
        parts = []
        while isinstance(func, ast.Attribute):
            parts.append(func.attr)
            func = func.value
        if isinstance(func, ast.Name):
            parts.append("os" if func.id in self.os_names else func.id)
            return ".".join(reversed(parts))
        return ""

    @staticmethod
    def _pjoin(parts: list[str]) -> str:
        out = ""
        for part in parts:
            if part.startswith("/") or not out:
                out = part
            else:
                out = out.rstrip("/") + "/" + part
        return out

    def fold(self, node, depth: int = 0):
        """Best-effort string value of an expression; unknown parts become _HOLE. None = not a string."""
        ast = self.ast
        if depth > 25:
            return None
        nxt = depth + 1
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return node.value
            if isinstance(node.value, bytes):
                return node.value.decode("latin-1")
            return None
        if isinstance(node, ast.Name):
            return self.consts.get(node.id)
        if isinstance(node, ast.JoinedStr):
            out = []
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    folded = self.fold(value.value, nxt)
                    out.append(folded if folded is not None and _HOLE not in folded else _HOLE)
                else:
                    out.append(self.fold(value, nxt) or "")
            return "".join(out)
        if isinstance(node, ast.BinOp):
            left, right = self.fold(node.left, nxt), self.fold(node.right, nxt)
            if isinstance(node.op, ast.Add) and (left is not None or right is not None):
                return (left if left is not None else _HOLE) + (right if right is not None else _HOLE)
            if isinstance(node.op, ast.Div) and (left is not None or right is not None):
                return self._pjoin([left if left is not None else _HOLE, right if right is not None else _HOLE])
            if isinstance(node.op, ast.Mod) and left is not None:
                args = node.right.elts if isinstance(node.right, ast.Tuple) else [node.right]
                return self._fill(re.sub(r"%[-#0 +]*\d*(?:\.\d+)?[sdirfx]", "\x01", left), args, nxt)
            return None
        if isinstance(node, ast.Subscript):
            arg = self._env_lookup_arg(node)
            return "~" if arg is not None and self.fold(arg, nxt) == "HOME" else None
        if isinstance(node, ast.Attribute):
            return "/" if node.attr == "sep" and self._is_os(node.value) else None
        if isinstance(node, ast.Call):
            return self._fold_call(node, nxt)
        return None

    def _fill(self, template: str, args: list, depth: int) -> str:
        values = [self.fold(a, depth) for a in args]
        pieces = template.split("\x01")
        out = pieces[0]
        for i, piece in enumerate(pieces[1:]):
            value = values[i] if i < len(values) else None
            out += (value if value is not None else _HOLE) + piece
        return out

    def _fold_call(self, node, depth: int):
        ast = self.ast
        func = node.func
        name = self._call_name(func)
        arg = self._env_lookup_arg(node)
        if arg is not None:
            return "~" if self.fold(arg, depth) == "HOME" else None
        if isinstance(func, ast.Attribute) and func.attr == "format":
            template = self.fold(func.value, depth)
            if template is not None:
                return self._fill(re.sub(r"\{[^{}]*\}", "\x01", template), list(node.args), depth)
        if isinstance(func, ast.Attribute) and func.attr == "join" and len(node.args) == 1 and name not in ("os.path.join", "posixpath.join"):
            sep = self.fold(func.value, depth)
            seq = node.args[0]
            if sep is not None and isinstance(seq, (ast.List, ast.Tuple)):
                return sep.join(self._or_hole(e, depth) for e in seq.elts)
        if name in ("os.path.join", "posixpath.join") or func_attr(func) == "joinpath":
            parts = [self._or_hole(a, depth) for a in node.args]
            if func_attr(func) == "joinpath":
                parts = [self._or_hole(func.value, depth)] + parts
            return self._pjoin(parts)
        if name in ("Path.home", "pathlib.Path.home", "os.path.expanduser") and not node.args:
            return "~"
        if name in ("Path", "pathlib.Path", "PurePath", "PosixPath", "os.path.expanduser", "os.path.abspath",
                    "os.path.realpath", "os.path.normpath", "os.fspath", "str", "open", "io.open"):
            if name == "os.path.expanduser" and node.args and self.fold(node.args[0], depth) == "~":
                return "~"
            return self._pjoin([self._or_hole(a, depth) for a in node.args]) if node.args else None
        if isinstance(func, ast.Attribute) and func.attr in ("expanduser", "resolve", "absolute", "read_text", "read_bytes", "open"):
            return self.fold(func.value, depth)
        return None

    def _or_hole(self, node, depth: int) -> str:
        folded = self.fold(node, depth)
        return folded if folded is not None else _HOLE

    # pass 2 ---------------------------------------------------------------
    def _check(self, node) -> None:
        ast = self.ast
        arg = self._env_lookup_arg(node)
        if arg is not None:
            name = self.fold(arg)
            if name is not None and _hole_name_is_secret(name):
                self.kinds.add("env")
        if self._is_bulk(node):
            self.kinds.add("bulk")
        if isinstance(node, (ast.Call, ast.BinOp, ast.JoinedStr)):
            value = self.fold(node)
            if value and (SENSITIVE_PATH.search(value.replace(_HOLE, "x")) or _PROC_ENVIRON_TEXT_RE.search(value)):
                self.kinds.add("path")

    def _is_bulk(self, node) -> bool:
        ast = self.ast
        if isinstance(node, ast.Call):
            func = node.func
            name = self._call_name(func)
            if node.args and self._is_environ(node.args[0]) and name in ("dict", "str", "repr", "json.dumps", "pickle.dumps", "marshal.dumps"):
                return True
            if isinstance(func, ast.Attribute) and func.attr in ("copy", "items", "values") and self._is_environ(func.value):
                return True
        if isinstance(node, ast.Dict):
            return any(k is None and self._is_environ(v) for k, v in zip(node.keys, node.values, strict=True))
        if isinstance(node, ast.Attribute) and node.attr == "_data" and self._is_environ(node.value):
            return True
        if isinstance(node, (ast.For, ast.comprehension)):
            source = node.iter
            if isinstance(source, ast.Call) and isinstance(source.func, ast.Attribute) and source.func.attr == "keys":
                source = source.func.value
            if self._is_environ(source):
                body = node.body if isinstance(node, ast.For) else []
                return any(self._env_lookup_arg(sub) is not None for stmt in body for sub in ast.walk(stmt))
        return False


def func_attr(func) -> str:
    """Attribute name of a call target (`x.joinpath` -> 'joinpath'), else ''."""
    return getattr(func, "attr", "") if func.__class__.__name__ == "Attribute" else ""


def _hole_name_is_secret(name: str) -> bool:
    """Secret test for an env name that may contain unresolved parts (_HOLE)."""
    upper = name.upper()
    if _HOLE not in upper:
        return _env_name_is_secret(upper)
    if _PROVIDER_PREFIX_RE.search(upper):
        return True
    fixed = upper.replace(_HOLE, "")
    return bool(_SECRET_NAME_PART_RE.search(fixed)) or fixed.endswith(("_TOKEN", "_KEY"))


# Interpreter-provided library folders (e.g. Ubuntu's python3-attr). Read-only in the sandbox, so
# code there cannot belong to the scanned package, which is installed under /w.
_SYSTEM_LIB_RE = re.compile(r"^/usr/(?:local/)?lib(?:64)?/python3(?:\.\d+)?/(?:dist|site)-packages/")


def _system_lib_codegen(e: dict) -> bool:
    """dyn.exec/dyn.compile emitted from a system library's own code generation (attrs, etc.).

    Older agents labelled these `pkg`. They are toolchain noise unless a canary is involved.
    """
    if e.get("kind") not in ("dyn.exec", "dyn.compile") or e.get("canary_match"):
        return False
    evidence_file = str((e.get("evidence") or {}).get("file") or "")
    return bool(_SYSTEM_LIB_RE.match(evidence_file))


def _home(p: str) -> str:
    p = p.replace("/w/home/", "~/").replace("/w/home", "~")
    return p


def _load_whitelist() -> list[dict]:
    rules: list[dict] = []
    for f in (Path(__file__).resolve().parent.parent / "engine" / "noise_whitelist.yaml", ROOT / "bench" / "calibration" / "noise_whitelist.yaml"):
        if f.exists():
            rules += (yaml.safe_load(f.read_text()) or {}).get("rules", [])
    return rules


def _whitelisted(cap: str, detail: dict, rules: list[dict], has_canary: bool = False) -> bool:
    if has_canary:
        return False
    for r in rules:
        if r.get("capability") != cap:
            continue
        for key, field in (("path_glob", "path"), ("host_glob", "host"), ("env_glob", "name")):
            if key in r and fnmatch.fnmatch(str(detail.get(field, detail.get("dest", ""))), r[key]):
                return True
    return False


def classify(e: dict, written_paths: set[str] | None = None, net_seen: set[tuple[str, str]] | None = None) -> tuple[str | None, dict]:
    """raw event -> (capability or None to drop, normalized detail)."""
    k = e.get("kind")
    d = dict(e.get("detail") or {})
    if not k:
        return None, d
    cm = list(e.get("canary_match") or [])
    # Canary promotion is only for reads. file.write/file.new must still reach PERSIST_PATH.
    if cm and k == "file.read":
        p = _home(d.get("path", ""))
        d["path"] = p
        return "fs_read_sensitive", d
    if cm and k == "env.read":
        return "env_secrets", d
    if k == "file.read":
        p = _home(d.get("path", ""))
        d["path"] = p
        if p in PROBE_PATH:
            return "sandbox_probe", d
        if PROC_ENVIRON_PATH.match(p):
            # The whole environment, secrets included, read as a file.
            d["name"] = "*"
            return "env_secrets", d
        return ("fs_read_sensitive", d) if SENSITIVE_PATH.search(p) else (None, d)
    if k in ("file.write", "file.new"):
        p = _home(d.get("path", ""))
        d["path"] = p
        if PERSIST_PATH.search(p):
            return "persistence", d
        return (None, d) if SAFE_WRITE.match(p) or not p.startswith(("~", "/")) else ("fs_write_outside_pkg", d)
    if k in ("net.dns", "net.connect", "net.send", "net.http"):
        if e.get("canary_match"):
            d["canary_in_bytes"] = True
        return "network", d
    if k == "proc.spawn":
        argv = d.get("argv") or []
        argv_str = " ".join(argv) if isinstance(argv, list) else str(argv)
        via = str(d.get("via", ""))
        if written_paths and any(wp for wp in written_paths if wp and (wp in argv_str or wp in via or any(wp == arg or arg.endswith("/" + Path(wp).name) for arg in (argv if isinstance(argv, list) else [])))):
            d["lineage"] = "download_exec"
            return "download_exec", d
        if d.get("lineage") == "download_exec":
            return "download_exec", d
        return "subprocess", d
    if k == "env.read":
        n = d.get("name", "")
        if n in PROBE_ENV:
            return "sandbox_probe", d
        return ("env_secrets", d) if SECRET_ENV.search(n) else (None, d)
    if k in ("dyn.exec", "dyn.compile"):
        co_fn = str(d.get("co_filename", ""))
        prof_var = (e.get("profile", ""), e.get("variant", ""))
        has_net = net_seen and prof_var in net_seen
        has_written = written_paths and any(wp for wp in written_paths if wp and (wp == co_fn or co_fn.endswith(wp)))
        if has_written or has_net:
            d["lineage"] = "download_exec"
            return "download_exec", d
        return "dynamic_exec", d
    if k == "install.hook":
        return "install_hook", d
    if k == "startup.sitecustomize":
        d["executes_code"] = True
        return "startup_hook", d
    if k == "startup.pth":
        line = str(d.get("line_text", "")).strip()
        if not line:
            return None, d
        is_exec = (
            line.startswith(("import ", "import\t"))
            or any(kw in line for kw in ("exec(", "eval(", "base64", "__import__"))
            or (";" in line and "import" in line)
        )
        if is_exec:
            d["executes_code"] = True
            return "startup_hook", d
        d["executes_code"] = False
        d["path_only"] = True
        return "startup_hook", d
    if k == "native.load":
        return "native_code", d
    return None, d


def build_fingerprint(raw_events_path: str, run_meta: dict, package: dict, static_signals: list[dict] | None = None,
                      whitelist: list[dict] | None = None) -> dict:
    rules = _load_whitelist() if whitelist is None else whitelist
    events, dropped = [], 0
    written_paths: set[str] = set()
    net_seen: set[tuple[str, str]] = set()
    seen_events: dict[tuple, int] = {}
    cov_coverage = copy.deepcopy(run_meta.get("coverage") or {})

    for e in iter_jsonl(raw_events_path):
        if not isinstance(e, dict):
            continue
        if e.get("detail") is None:
            e["detail"] = {}
        is_toolchain = e.get("attributed_to") == "toolchain" or _system_lib_codegen(e)
        if e.get("kind") == "run.error":
            cov_coverage["run_error"] = True
            msg = str(e.get("detail", {}).get("message", ""))
            if "timeout" in msg.lower():
                cov_coverage["run_timeout"] = True
            not_obs = cov_coverage.setdefault("not_observed", [])
            phase = e.get("phase", "execution")
            err_line = f"Error during {phase}: {msg}" if msg else f"Error during {phase}"
            if err_line not in not_obs:
                not_obs.append(err_line)

        if is_toolchain:
            dropped += 1
            continue
        if e.get("kind") in ("file.write", "file.new"):
            wp = _home(e.get("detail", {}).get("path", ""))
            if wp:
                written_paths.add(wp)
        if e.get("kind") in ("net.http", "net.send"):
            net_seen.add((e.get("profile", ""), e.get("variant", "")))

        cap, detail = classify(e, written_paths, net_seen)
        cm = list(e.get("canary_match") or [])
        has_canary = bool(cm) or bool(detail.get("canary_in_bytes"))

        if has_canary and cap is None:
            if str(e.get("kind", "")).startswith("env."):
                cap = "env_secrets"
            else:
                cap = "fs_read_sensitive"

        if not has_canary and (cap is None or _whitelisted(cap, detail, rules, has_canary=has_canary)):
            dropped += 1
            continue

        detail_target = str(detail.get("path") or detail.get("name") or detail.get("dest") or detail.get("host") or detail.get("url") or detail.get("argv") or detail.get("file") or "")
        dedupe_key = (
            e["phase"], e["trigger"], e["profile"], e["variant"],
            cap, e["outcome"], e.get("attributed_to", "unknown"),
            detail_target,
            detail.get("decoded_snippet"),
            detail.get("co_filename"),
            detail.get("url"),
            detail.get("host"),
            detail.get("dest"),
            bool(cm)
        )
        if dedupe_key in seen_events:
            idx = seen_events[dedupe_key]
            existing_ev = events[idx]
            existing_ev["detail"]["count"] = existing_ev["detail"].get("count", 1) + 1
            existing_ev["count"] = existing_ev.get("count", 1) + 1
            for cid in cm:
                if cid not in existing_ev["canary_ids"]:
                    existing_ev["canary_ids"].append(cid)
            dropped += 1
            continue

        ev_idx = len(events)
        seen_events[dedupe_key] = ev_idx
        events.append({
            "id": f"ev{ev_idx}", "seq": e["seq"], "phase": e["phase"], "trigger": e["trigger"],
            "profile": e["profile"], "variant": e["variant"], "capability": cap, "detail": detail,
            "canary_hit": bool(cm), "canary_ids": cm, "outcome": e["outcome"],
            "attributed_to": e.get("attributed_to", "unknown"), "evidence": e.get("evidence") or {}
        })
    combos = {(p, v) for p in run_meta["coverage"]["profiles_run"] for v in (run_meta["coverage"].get("variants_run") or ["default"])}
    summary: dict[str, dict] = {}
    for cap in sorted({ev["capability"] for ev in events}):
        evs = [ev for ev in events if ev["capability"] == cap]
        seen = {(ev["profile"], ev["variant"]) for ev in evs}
        summary[cap] = {"phases": sorted({ev["phase"] for ev in evs}), "profiles": sorted({ev["profile"] for ev in evs}),
                        "conditional": bool(combos) and seen != combos, "count": len(evs), "canary_hit": any(ev["canary_hit"] for ev in evs)}
    cov = dict(cov_coverage, whitelisted_or_dropped_events=dropped)
    return {"schema_version": "1.0", "package": package, "run": run_meta.get("run", {}), "events": events, "static_signals": list(static_signals or []),
            "coverage": cov, "canaries": run_meta.get("canaries", []), "capability_summary": summary}
