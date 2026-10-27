"""Static AST and behavioral code scanner for TrustLens.
Inspects Python package source files to detect sensitive file access, network activity,
obfuscation, dynamic execution, subprocesses, and environment harvesting.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SENSITIVE_PATHS = (
    "id_rsa",
    "id_ed25519",
    ".ssh",
    ".aws",
    "credentials",
    ".env",
    "token",
    "shadow",
    "passwd",
    "bash_history",
)

NETWORK_MODULES = ("socket", "urllib", "requests", "http.client", "aiohttp", "httpx", "urllib3")
SUBPROCESS_MODULES = ("subprocess", "os.system", "os.popen", "pty")


@dataclass
class StaticSignal:
    rule: str
    severity: str
    file: str
    line: int
    detail: str
    capability: str
    score: float = 5.0


@dataclass
class StaticScanResult:
    signals: list[StaticSignal] = field(default_factory=list)
    has_pth_hook: bool = False
    has_eval_exec: bool = False
    has_obfuscation: bool = False
    has_sensitive_file_access: bool = False
    has_network_code: bool = False
    has_subprocess: bool = False
    has_env_harvesting: bool = False
    has_gate: bool = False
    files_scanned: int = 0
    total_lines: int = 0


class PackageASTVisitor(ast.NodeVisitor):
    def __init__(self, filename: str):
        self.filename = filename
        self.signals: list[StaticSignal] = []

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.name
            if name in NETWORK_MODULES:
                self.signals.append(
                    StaticSignal(
                        rule="static_network_import",
                        severity="medium",
                        file=self.filename,
                        line=node.lineno,
                        detail=f"Imports network library: {name}",
                        capability="network",
                        score=4.0,
                    )
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        mod = node.module or ""
        for name in NETWORK_MODULES:
            if mod.startswith(name):
                self.signals.append(
                    StaticSignal(
                        rule="static_network_import",
                        severity="medium",
                        file=self.filename,
                        line=node.lineno,
                        detail=f"Imports from network library: {mod}",
                        capability="network",
                        score=4.0,
                    )
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        # 1. exec / eval / compile
        if func_name in ("exec", "eval", "compile"):
            self.signals.append(
                StaticSignal(
                    rule="decoded_exec",
                    severity="critical",
                    file=self.filename,
                    line=node.lineno,
                    detail=f"Dynamic code execution via '{func_name}()'",
                    capability="dynamic_exec",
                    score=12.0,
                )
            )

        # 2. b64decode / base64
        if func_name in ("b64decode", "decodebytes", "a2b_base64"):
            self.signals.append(
                StaticSignal(
                    rule="obfuscated_payload",
                    severity="high",
                    file=self.filename,
                    line=node.lineno,
                    detail=f"Base64 decoding invocation via '{func_name}()'",
                    capability="dynamic_exec",
                    score=8.0,
                )
            )

        # 3. subprocess / os.system
        if func_name in ("system", "popen", "run", "Popen", "call", "check_output"):
            self.signals.append(
                StaticSignal(
                    rule="subprocess_spawn",
                    severity="medium",
                    file=self.filename,
                    line=node.lineno,
                    detail=f"Subprocess/system call invocation via '{func_name}()'",
                    capability="subprocess",
                    score=6.0,
                )
            )

        # 4. Environment variable harvesting
        if func_name in ("environ", "getenv"):
            self.signals.append(
                StaticSignal(
                    rule="env_harvesting",
                    severity="medium",
                    file=self.filename,
                    line=node.lineno,
                    detail=f"Accesses environment variables via '{func_name}'",
                    capability="env_secrets",
                    score=5.0,
                )
            )

        # 5. Gating mechanisms (gethostname, datetime checks)
        if func_name in ("gethostname", "node"):
            self.signals.append(
                StaticSignal(
                    rule="host_gate",
                    severity="high",
                    file=self.filename,
                    line=node.lineno,
                    detail="Queries host machine identity (potential environment evasion)",
                    capability="sandbox_probe",
                    score=7.0,
                )
            )

        # 6. Check string arguments for sensitive file paths
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                sval = arg.value
                for sp in SENSITIVE_PATHS:
                    if sp in sval:
                        self.signals.append(
                            StaticSignal(
                                rule="canary_access",
                                severity="critical",
                                file=self.filename,
                                line=node.lineno,
                                detail=f"Reference to sensitive credential path: '{sval}'",
                                capability="fs_read_sensitive",
                                score=12.0,
                            )
                        )
                        break

        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp):
        # Detect bitwise XOR on character codes (common in python obfuscation)
        if isinstance(node.op, ast.BitXor):
            self.signals.append(
                StaticSignal(
                    rule="bitwise_xor_obfuscation",
                    severity="medium",
                    file=self.filename,
                    line=node.lineno,
                    detail="Bitwise XOR operations (common in payload decoders)",
                    capability="dynamic_exec",
                    score=5.0,
                )
            )
        self.generic_visit(node)


def scan_package_static(pkg_dir: Path) -> StaticScanResult:
    """Recursively scan all Python files and package manifests in directory."""
    result = StaticScanResult()
    root = pkg_dir.resolve()

    # Check for .pth startup files
    for item in root.glob("*.pth"):
        result.has_pth_hook = True
        result.signals.append(
            StaticSignal(
                rule="startup_hook",
                severity="critical",
                file=str(item.relative_to(root)),
                line=1,
                detail=f"Startup hook file detected: '{item.name}' (executes code on python startup)",
                capability="startup_hook",
                score=12.0,
            )
        )

    # Walk python files
    for p in root.rglob("*.py"):
        if ".git" in p.parts or "__pycache__" in p.parts or ".venv" in p.parts:
            continue
        result.files_scanned += 1
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
            result.total_lines += len(content.splitlines())
            rel_file = str(p.relative_to(root))

            # Fast regex search for IP targets / URLs
            if re.search(r"198\.51\.100\.\d+|exfil\.invalid|payload\.invalid", content):
                result.signals.append(
                    StaticSignal(
                        rule="network_unclaimed",
                        severity="high",
                        file=rel_file,
                        line=1,
                        detail="Hardcoded RFC 5737 test-net exfiltration IP or payload domain found",
                        capability="network",
                        score=10.0,
                    )
                )

            # AST parse
            tree = ast.parse(content, filename=rel_file)
            visitor = PackageASTVisitor(rel_file)
            visitor.visit(tree)
            result.signals.extend(visitor.signals)

        except Exception:
            # Skip invalid syntax in older/experimental python files
            continue

    # Deduplicate signals by (rule, file, line)
    seen = set()
    deduped = []
    for sig in result.signals:
        key = (sig.rule, sig.file, sig.line)
        if key not in seen:
            seen.add(key)
            deduped.append(sig)
    result.signals = deduped

    # Aggregate flags
    for s in result.signals:
        if s.capability == "dynamic_exec":
            result.has_eval_exec = True
        if s.capability == "network":
            result.has_network_code = True
        if s.capability == "fs_read_sensitive":
            result.has_sensitive_file_access = True
        if s.capability == "subprocess":
            result.has_subprocess = True
        if s.capability == "env_secrets":
            result.has_env_harvesting = True
        if s.rule in ("bitwise_xor_obfuscation", "obfuscated_payload"):
            result.has_obfuscation = True
        if s.rule in ("host_gate", "time_gate"):
            result.has_gate = True

    return result
