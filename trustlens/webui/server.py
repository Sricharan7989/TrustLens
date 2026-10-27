"""TrustLens Localhost-only Web UI console.
Features a luxury monochromatic obsidian aesthetic matching the landing page.
Displays exclusively the security report with a minimalist top dependency search bar.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import tempfile
import threading
from email.parser import BytesParser
from email.policy import default
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from trustlens.cli import scan
from trustlens.contracts import OUTPUT_ROOT, ROOT
from trustlens.llm.reporter import generate_llm_report
from trustlens.ml.threat_model import get_threat_model
from trustlens.report import render_comparison_html
from trustlens.report.redact import redact_document
from trustlens.resolver import resolve_package
from trustlens.sandbox.env_check import check_env
from trustlens.static.ast_analyzer import scan_package_static

MAX_UPLOAD_SIZE = 20 * 1024 * 1024  # 20 MB
scan_lock = threading.Lock()
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "[::1]"})

logger = logging.getLogger("trustlens.webui")


def host_is_loopback(host_header: str) -> bool:
    value = (host_header or "").strip().lower()
    if not value:
        return False
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            return False
        name = value[: end + 1]
        rest = value[end + 1 :]
        if rest and not re.fullmatch(r":\d+", rest):
            return False
        return name in _LOOPBACK_HOSTS
    if value.count(":") == 1:
        name, port = value.rsplit(":", 1)
        if port.isdigit():
            value = name
    return value in _LOOPBACK_HOSTS


def _rejected_upload_name(raw_fn: str) -> bool:
    """True when the upload basename is `.` or `..` (pathlib collapses `.` to an empty name)."""
    if raw_fn in {".", ".."}:
        return True
    return Path(raw_fn).name in {".", ".."}


DEMO_PACKAGES = [
    {"id": "evil_slug", "name": "evil-slug (malicious / install-time exfil)", "path": "bench/packages/malicious/evil_slug"},
    {"id": "delayed_slug", "name": "delayed-slug (malicious / CI-gated exfil)", "path": "bench/packages/malicious/delayed_slug"},
    {"id": "clean_slug", "name": "clean-slug (clean control)", "path": "bench/packages/clean/clean_slug"},
    {"id": "rest_wrapper", "name": "rest-wrapper (clean / noisy-benign REST client)", "path": "bench/packages/clean/rest_wrapper"},
]


def bench_packages() -> list[dict]:
    """Every bench/labels.yaml package present in this checkout (none in a pip install).
    Falls back to DEMO_PACKAGES when the labels file is missing or unreadable.
    """
    labels = ROOT / "bench" / "labels.yaml"
    try:
        import yaml

        rows = yaml.safe_load(labels.read_text(encoding="utf-8"))["packages"]
        found = [
            {"id": r["id"], "name": f"{r['id']} ({r.get('label', '?')} / {r.get('category', '?')})",
             "path": r["path"], "label": r.get("label", "")}
            for r in rows if (ROOT / r["path"]).is_dir()
        ]
        if found:
            return found
    except (OSError, KeyError, TypeError, ValueError):
        pass
    return [d for d in DEMO_PACKAGES if (ROOT / d["path"]).is_dir()]


HTML_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>TrustLens AI - Localhost Provenance Console</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #000000;
      --surface: #0D0D0D;
      --surface-raised: #141414;
      --border: rgba(255, 255, 255, 0.12);
      --border-bright: rgba(255, 255, 255, 0.4);
      --text: #FFFFFF;
      --text-muted: #A6A6AC;
      --primary: #8b5cf6;
      --pass: #10b981;
      --block: #ef4444;
      --review: #f59e0b;
      --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-sans);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      overflow-x: hidden;
    }
    .topbar {
      background: rgba(13, 13, 13, 0.85);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border-bottom: 1px solid var(--border);
      padding: 0.9rem 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 50;
      gap: 1.5rem;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      white-space: nowrap;
    }
    .brand-logo {
      width: 28px;
      height: 28px;
      background: #FFFFFF;
      color: #000000;
      border-radius: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 900;
      font-size: 1.1rem;
    }
    .brand-title {
      font-size: 1.05rem;
      font-weight: 700;
      letter-spacing: -0.01em;
    }
    .brand-tag {
      font-size: 0.75rem;
      font-family: var(--font-mono);
      color: var(--text-muted);
      background: rgba(255, 255, 255, 0.06);
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      border: 1px solid var(--border);
    }
    .search-wrap {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      flex: 1;
      max-width: 600px;
    }
    .search-input {
      flex: 1;
      background: var(--surface-raised);
      border: 1px solid var(--border);
      border-radius: 8px;
      color: var(--text);
      padding: 0.55rem 1rem;
      font-size: 0.9rem;
      font-family: var(--font-mono);
      outline: none;
      transition: all 0.2s ease;
    }
    .search-input:focus {
      border-color: var(--border-bright);
      box-shadow: 0 0 20px -5px rgba(139, 92, 246, 0.4);
    }
    .btn-scan {
      background: #FFFFFF;
      color: #000000;
      border: none;
      border-radius: 8px;
      padding: 0.55rem 1.25rem;
      font-weight: 600;
      font-size: 0.88rem;
      cursor: pointer;
      transition: all 0.2s ease;
      white-space: nowrap;
    }
    .btn-scan:hover {
      background: #E0E0E4;
      transform: translateY(-1px);
    }
    .pills-bar {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 0.8rem;
    }
    .pill {
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid var(--border);
      color: var(--text-muted);
      padding: 0.25rem 0.65rem;
      border-radius: 9999px;
      cursor: pointer;
      transition: all 0.2s ease;
      font-family: var(--font-mono);
      font-size: 0.75rem;
    }
    .pill:hover {
      background: rgba(255, 255, 255, 0.12);
      color: #FFFFFF;
      border-color: var(--border-bright);
    }
    #status-bar {
      display: none;
      padding: 0.65rem 2rem;
      font-size: 0.88rem;
      font-family: var(--font-mono);
      border-bottom: 1px solid var(--border);
      background: rgba(139, 92, 246, 0.12);
      color: #c4b5fd;
    }
    #status-bar.error {
      background: rgba(239, 68, 68, 0.12);
      color: #f87171;
    }
    .report-viewport {
      flex: 1;
      width: 100%;
      height: calc(100vh - 65px);
      position: relative;
      background: #000000;
    }
    iframe.report-frame {
      width: 100%;
      height: 100%;
      border: none;
      display: block;
    }
  </style>
</head>
<body>
  <div class="topbar">
    <div class="brand">
      <div class="brand-logo">◈</div>
      <div class="brand-title">TrustLens AI</div>
      <div class="brand-tag">Provenance Console</div>
    </div>

    <div class="search-wrap">
      <input type="text" id="pkg-input" class="search-input" placeholder="Scan PyPI package or toy (e.g. requests, evil_slug)..." value="">
      <button id="btn-scan" class="btn-scan">Run Behavioral Scan</button>
    </div>

    <div class="pills-bar">
      <span style="color: var(--text-muted);">Quick:</span>
      <span class="pill" onclick="scanPill('evil_slug')">evil_slug</span>
      <span class="pill" onclick="scanPill('clean_slug')">clean_slug</span>
      <span class="pill" onclick="scanPill('rest_wrapper')">rest_wrapper</span>
      <span class="pill" onclick="scanPill('delayed_slug')">delayed_slug</span>
      <span class="pill" onclick="scanPill('requests')">requests</span>
    </div>
  </div>

  <div id="status-bar"></div>

  <div class="report-viewport">
    <iframe id="report-iframe" name="report-frame" class="report-frame" sandbox="allow-scripts allow-same-origin" src="about:blank"></iframe>
  </div>

  <script>
    let scanSeq = 0;

    function escapeText(t) {
      return String(t).replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
    }

    function showPlaceholder(msg) {
      const frame = document.getElementById('report-iframe') || document.getElementById('report-frame');
      if (frame) {
        frame.srcdoc = "<p style='font-family:sans-serif;color:#888;padding:2rem'>" + escapeText(msg) + "</p>";
      }
    }

    function setBusy(busy) {
      ['btn-scan', 'btn-scan-preset', 'btn-compare'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.disabled = busy;
      });
    }

    function setStatus(text, isError) {
      const sb = document.getElementById('status-bar');
      if (!text) {
        sb.style.display = 'none';
        return;
      }
      sb.textContent = text;
      sb.className = isError ? 'error' : '';
      sb.style.display = 'block';
    }

    function showResult(seq, label, data) {
      if (seq !== scanSeq) return;
      setBusy(false);
      const btn = document.getElementById('btn-scan');
      if (btn) btn.textContent = 'Run Behavioral Scan';
      if (data.error) {
        setStatus('❌ ' + label + ': ' + data.error, true);
        showPlaceholder('No report for ' + label + ': ' + data.error);
        return;
      }
      const v = data.verdict || {};
      const who = v.package ? (v.package.name + ' ' + (v.package.version || '')) : label;
      setStatus('✔ Report for ' + who + ': ' + (v.verdict || '') + ' (' + (v.action || '') + ')', false);
      const frame = document.getElementById('report-iframe') || document.getElementById('report-frame');
      if (frame) frame.srcdoc = data.report_html;
    }

    async function triggerScan(pkgName) {
      if (!pkgName || !pkgName.trim()) return;
      const target = pkgName.trim();
      const label = target.split('/').pop();
      const seq = ++scanSeq;
      setBusy(true);
      const btn = document.getElementById('btn-scan');
      if (btn) btn.textContent = 'Analyzing...';
      setStatus('⚡ Fetching package files, parsing claims, and executing XGBoost & Gemini analysis for ' + label + '...', false);
      showPlaceholder('Scanning ' + label + '... the report for this package will appear here.');

      try {
        const res = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ package: target })
        });
        showResult(seq, label, await res.json());
      } catch (err) {
        showResult(seq, label, { error: 'network error: ' + err.message });
      }
    }

    const runScan = triggerScan;

    function scanPill(name) {
      document.getElementById('pkg-input').value = name;
      triggerScan(name);
    }

    document.getElementById('btn-scan').addEventListener('click', () => {
      triggerScan(document.getElementById('pkg-input').value);
    });

    document.getElementById('pkg-input').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        triggerScan(e.target.value);
      }
    });

    window.addEventListener('DOMContentLoaded', () => {
      // No automatic scan: the report area stays empty until a package is chosen
    });
  </script>
</body>
</html>"""


class TrustLensWebHandler(BaseHTTPRequestHandler):
    def _validate_host(self) -> bool:
        if not host_is_loopback(self.headers.get("Host", "")):
            self.send_error(HTTPStatus.FORBIDDEN, "Forbidden: Web UI binds exclusively to loopback (127.0.0.1).")
            return False
        return True

    def do_GET(self) -> None:
        if not self._validate_host():
            return

        if self.path == "/" or self.path.startswith("/?"):
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src 'self' https://fonts.gstatic.com data:; frame-src 'self' data: about:;")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode("utf-8"))
            return

        if self.path == "/api/status":
            env = check_env()
            resp = {
                "bwrap_ok": bool(env.get("bwrap_ok")),
                "demo_packages": bench_packages(),
            }
            self._send_json(resp)
            return

        if self.path == "/api/compare-demo":
            clean_path = ROOT / "bench/packages/clean/rest_wrapper"
            mal_path = ROOT / "bench/packages/malicious/evil_slug"
            out_c = OUTPUT_ROOT / "reports/compare_tmp/clean"
            out_m = OUTPUT_ROOT / "reports/compare_tmp/malicious"

            with scan_lock:
                rc = scan(str(clean_path), str(out_c), runner="fixture", offline=True)
                rm = scan(str(mal_path), str(out_m), runner="fixture", offline=True)

            comp_html = render_comparison_html(
                rc["verdict"], rc["fingerprint"], rc["claims"],
                rm["verdict"], rm["fingerprint"], rm["claims"]
            )
            body = comp_html.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def do_POST(self) -> None:
        if not self._validate_host():
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid Content-Length")
            return

        if content_length < 0 or content_length > MAX_UPLOAD_SIZE:
            self.send_error(HTTPStatus.BAD_REQUEST, "Content-Length must be between 0 and 20MB.")
            return

        if self.path == "/api/scan":
            body = self.rfile.read(content_length)
            try:
                payload = json.loads(body.decode("utf-8"))
            except Exception as e:
                self._send_json({"error": f"Invalid JSON payload: {e}"}, HTTPStatus.BAD_REQUEST)
                return

            pkg_query = payload.get("package", "").strip()
            if not pkg_query:
                self._send_json({"error": "Missing package query"}, HTTPStatus.BAD_REQUEST)
                return

            raw_path = Path(pkg_query)
            if (
                pkg_query.startswith(("/", "\\"))
                or raw_path.is_absolute()
                or ".." in raw_path.parts
                or (len(pkg_query) >= 2 and pkg_query[1] == ":")
            ):
                self._send_json({"error": f"Forbidden: path traversal or absolute path '{pkg_query}'"}, HTTPStatus.BAD_REQUEST)
                return

            with scan_lock:
                try:
                    bench_root = (ROOT / "bench/packages").resolve()
                    upload_root = (OUTPUT_ROOT / "reports/webui/uploads").resolve()
                    base = OUTPUT_ROOT if raw_path.parts[:3] == ("reports", "webui", "uploads") else ROOT
                    cand_local = (base / raw_path).resolve()

                    if cand_local.exists():
                        try:
                            cand_local.relative_to(bench_root)
                            target_path = cand_local
                            pkg_name = cand_local.name
                        except ValueError:
                            try:
                                cand_local.relative_to(upload_root)
                                target_path = cand_local
                                pkg_name = cand_local.name
                            except ValueError:
                                self._send_json({"error": f"Forbidden: path must be inside bench/packages/ or uploads/: '{pkg_query}'"}, HTTPStatus.BAD_REQUEST)
                                return
                    else:
                        resolved = resolve_package(pkg_query)
                        target_path = resolved.local_path
                        pkg_name = resolved.name

                    profiles = payload.get("profiles", "dev,ci").split(",")
                    out_dir = OUTPUT_ROOT / "reports" / pkg_name

                    # Run scan
                    res = scan(str(target_path), str(out_dir), runner="auto", profiles=tuple(profiles), offline=True)
                    v = res["verdict"]
                    fp = res["fingerprint"]
                    cl = res["claims"]

                    # Static AST
                    static_res = scan_package_static(target_path)

                    # ML Threat Model
                    tm = get_threat_model()
                    pred = tm.predict(v, fp, cl, static_res)
                    v["ml_threat_score"] = pred.threat_score
                    v["ml_risk_tier"] = pred.risk_tier
                    v["ml_factors"] = pred.top_factors

                    # Gemini LLM Report
                    llm_rep = generate_llm_report(v, fp, cl, pred)
                    v["llm_report"] = llm_rep.report_markdown
                    v["llm_model"] = llm_rep.model_used

                    from trustlens.report import render_html
                    report_html = render_html(v, fp, cl)
                    (Path(out_dir) / "report.html").write_text(report_html, encoding="utf-8")

                    self._send_json({
                        "verdict": redact_document(v),
                        "report_html": report_html,
                    })
                except Exception as e:
                    self._send_json({"error": str(e)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if self.path == "/api/upload":
            ctype = self.headers.get("Content-Type", "")
            if not ctype.startswith("multipart/form-data"):
                self.send_error(HTTPStatus.BAD_REQUEST, "Expected multipart/form-data")
                return

            body_bytes = self.rfile.read(content_length)
            msg = BytesParser(policy=default).parsebytes(
                b"Content-Type: " + ctype.encode("latin1") + b"\r\n\r\n" + body_bytes
            )

            file_bytes = None
            filename = None
            profiles = ["dev", "ci"]

            try:
                for part in msg.iter_parts():
                    cdisp = part.get("Content-Disposition", "")
                    if 'name="profiles"' in cdisp:
                        prof_val = part.get_content().strip()
                        if prof_val:
                            profiles = [p.strip() for p in prof_val.split(",") if p.strip()]
                    elif 'name="file"' in cdisp or part.get_filename():
                        raw_fn = part.get_filename() or "uploaded_package.whl"
                        if _rejected_upload_name(raw_fn):
                            self._send_json(
                                {"error": "rejected upload filename '.' or '..'"},
                                HTTPStatus.BAD_REQUEST,
                            )
                            return
                        clean_name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', Path(raw_fn).name)
                        if _rejected_upload_name(clean_name):
                            self._send_json(
                                {"error": "rejected upload filename '.' or '..'"},
                                HTTPStatus.BAD_REQUEST,
                            )
                            return
                        filename = clean_name or "uploaded_package.whl"
                        file_bytes = part.get_payload(decode=True)

                if not file_bytes or not filename:
                    self._send_json({"error": "No file uploaded in form field 'file'"}, HTTPStatus.BAD_REQUEST)
                    return

                with tempfile.TemporaryDirectory(prefix="trustlens_upload_") as tmp_dir:
                    tmp_file = Path(tmp_dir) / filename
                    if _rejected_upload_name(tmp_file.name) or Path(tmp_dir).resolve() not in tmp_file.resolve().parents:
                        self._send_json(
                            {"error": "rejected upload filename '.' or '..'"},
                            HTTPStatus.BAD_REQUEST,
                        )
                        return
                    tmp_file.write_bytes(file_bytes)
                    out_dir = OUTPUT_ROOT / "reports/webui/uploads" / filename

                    with scan_lock:
                        res = scan(str(tmp_file), str(out_dir), profiles=tuple(profiles), runner="auto", offline=True)
                        report_html = (Path(res["out_dir"]) / "report.html").read_text(encoding="utf-8")
                        self._send_json({"verdict": redact_document(res["verdict"]), "report_html": report_html})
            except Exception as e:
                self._send_json({"error": f"Scan failed: {e}"}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def _send_json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        # Keep server quiet unless debugging
        pass


def create_server(host: str = "127.0.0.1", port: int = 8765) -> HTTPServer:
    if not host_is_loopback(host):
        raise ValueError(f"Server refused to bind to non-loopback host: {host}")
    return HTTPServer((host, port), TrustLensWebHandler)


def run_server(host: str = "127.0.0.1", port: int = 8765) -> None:
    server = create_server(host, port)
    print(f"\n◈ TrustLens Provenance Console active at: http://{host}:{port}/")
    print("Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping TrustLens Provenance Console.")
        server.server_close()
