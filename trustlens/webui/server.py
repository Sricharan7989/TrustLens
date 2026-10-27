"""Dev D: Localhost-only Web UI server using standard library http.server.
Pure Python, offline, zero CDN dependencies, strict loopback binding (127.0.0.1).
"""
from __future__ import annotations

import json
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
from trustlens.contracts import ROOT
from trustlens.report import render_comparison_html
from trustlens.sandbox.env_check import check_env

MAX_UPLOAD_SIZE = 20 * 1024 * 1024  # 20 MB
scan_lock = threading.Lock()

DEMO_PACKAGES = [
    {"id": "evil_slug", "name": "evil-slug (malicious / install-time exfil)", "path": "bench/packages/malicious/evil_slug"},
    {"id": "delayed_slug", "name": "delayed-slug (malicious / CI-gated exfil)", "path": "bench/packages/malicious/delayed_slug"},
    {"id": "clean_slug", "name": "clean-slug (clean control)", "path": "bench/packages/clean/clean_slug"},
    {"id": "rest_wrapper", "name": "rest-wrapper (clean / noisy-benign REST client)", "path": "bench/packages/clean/rest_wrapper"},
]

HTML_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>TrustLens AI - Localhost Provenance Console</title>
  <style>
    :root {
      --bg: #0b0f19;
      --surface: #151d30;
      --surface-alt: #222f4c;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --border: #334155;
      --pass: #10b981;
      --block: #ef4444;
      --review: #f59e0b;
      --primary: #3b82f6;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 1.5rem;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 1rem;
      border-bottom: 1px solid var(--border);
      margin-bottom: 1.5rem;
    }
    .header h1 { font-size: 1.6rem; display: flex; align-items: center; gap: 0.5rem; }
    .badge-runner {
      background: var(--surface-alt);
      border: 1px solid var(--border);
      padding: 0.35rem 0.8rem;
      border-radius: 9999px;
      font-size: 0.85rem;
      font-weight: 600;
    }
    .badge-runner.live { border-color: var(--pass); color: var(--pass); }
    .badge-runner.fixture { border-color: var(--review); color: var(--review); }

    .grid-top {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1.5rem;
      margin-bottom: 1.5rem;
    }
    @media (max-width: 900px) { .grid-top { grid-template-columns: 1fr; } }

    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
    }
    .card h2 { font-size: 1.15rem; margin-bottom: 0.75rem; color: var(--text); }
    .form-group { margin-bottom: 1rem; }
    label { display: block; font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.35rem; }
    select, input[type="file"], input[type="text"] {
      width: 100%;
      background: var(--surface-alt);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 0.5rem 0.75rem;
      border-radius: 6px;
      font-size: 0.9rem;
    }
    .checkbox-group { display: flex; gap: 1rem; align-items: center; margin-top: 0.5rem; }
    .checkbox-group label { display: inline-flex; align-items: center; gap: 0.35rem; margin-bottom: 0; cursor: pointer; }

    .btn-row { display: flex; gap: 0.75rem; margin-top: 1rem; }
    .btn {
      background: var(--primary);
      color: #fff;
      border: none;
      padding: 0.6rem 1.2rem;
      border-radius: 6px;
      font-weight: 600;
      cursor: pointer;
      font-size: 0.9rem;
      transition: opacity 0.2s;
    }
    .btn:hover { opacity: 0.9; }
    .btn-secondary { background: var(--surface-alt); border: 1px solid var(--border); color: var(--text); }

    #status-banner {
      display: none;
      padding: 0.75rem 1rem;
      border-radius: 6px;
      margin-bottom: 1.5rem;
      font-size: 0.9rem;
    }
    #status-banner.running { display: block; background: #1e3a8a; border: 1px solid #3b82f6; }
    #status-banner.error { display: block; background: #7f1d1d; border: 1px solid var(--block); }

    .report-frame-wrap {
      width: 100%;
      height: 900px;
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
      background: #0f172a;
    }
    iframe { width: 100%; height: 100%; border: none; }
  </style>
</head>
<body>
  <div class="header">
    <h1>🛡️ TrustLens AI <span>Provenance Console</span></h1>
    <div id="runner-badge" class="badge-runner">Detecting Sandbox...</div>
  </div>

  <div class="grid-top">
    <!-- Preset Demo Packages -->
    <div class="card">
      <h2>1. Select Benchmark Package</h2>
      <div class="form-group">
        <label for="demo-select">Pre-configured Benchmark Samples:</label>
        <select id="demo-select">
          <option value="bench/packages/malicious/evil_slug">evil-slug (Malicious / Fake SSH & AWS Exfil)</option>
          <option value="bench/packages/malicious/delayed_slug">delayed-slug (Malicious / CI-Gated Base64 Exec)</option>
          <option value="bench/packages/clean/clean_slug">clean-slug (Clean Control / String Utility)</option>
          <option value="bench/packages/clean/rest_wrapper">rest-wrapper (Clean Control / Legitimate REST Client)</option>
        </select>
      </div>

      <div class="form-group">
        <label>Profiles to Exercise:</label>
        <div class="checkbox-group">
          <label><input type="checkbox" id="prof-dev" checked> Dev Laptop</label>
          <label><input type="checkbox" id="prof-ci" checked> CI Pipeline</label>
        </div>
      </div>

      <div class="btn-row">
        <button class="btn" id="btn-scan-preset">Run Behavioral Scan</button>
        <button class="btn btn-secondary" id="btn-compare">Side-by-Side (PASS vs BLOCK)</button>
      </div>
    </div>

    <!-- Archive Upload Zone -->
    <div class="card">
      <h2>2. Or Upload Archive (.whl / .tar.gz / .zip)</h2>
      <div class="form-group">
        <label for="file-upload">Upload Candidate Wheel or Sdist:</label>
        <input type="file" id="file-upload" accept=".whl,.zip,.tar.gz,.tgz">
      </div>
      <p style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 1rem;">
        Archives are extracted inside isolated temporary storage with path traversal filters. Zero package code executes on the host outside the sandbox.
      </p>
      <div class="btn-row">
        <button class="btn" id="btn-scan-upload">Upload &amp; Scan</button>
      </div>
    </div>
  </div>

  <div id="status-banner"></div>

  <div class="card" style="padding: 0.5rem;">
    <div class="report-frame-wrap">
      <iframe id="report-iframe" sandbox="allow-scripts" src="about:blank"></iframe>
    </div>
  </div>

  <script>
    async function loadStatus() {
      try {
        const res = await fetch('/api/status');
        const data = await res.json();
        const badge = document.getElementById('runner-badge');
        if (data.bwrap_ok) {
          badge.textContent = 'Runner: LIVE (bwrap sandbox)';
          badge.className = 'badge-runner live';
        } else {
          badge.textContent = 'Runner: RECORDED FIXTURE (stub replay)';
          badge.className = 'badge-runner fixture';
        }
      } catch (err) {
        console.error(err);
      }
    }

    function setStatus(msg, type) {
      const b = document.getElementById('status-banner');
      if (!msg) {
        b.style.display = 'none';
        return;
      }
      b.textContent = msg;
      b.className = type;
      b.style.display = 'block';
    }

    async function runScan(targetPath) {
      const dev = document.getElementById('prof-dev').checked;
      const ci = document.getElementById('prof-ci').checked;
      const profiles = [];
      if (dev) profiles.push('dev');
      if (ci) profiles.push('ci');

      setStatus('⏳ Running TrustLens behavioral sandbox & claims analysis...', 'running');
      try {
        const res = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ package: targetPath, profiles: profiles.join(',') })
        });
        const data = await res.json();
        if (data.error) {
          setStatus('❌ Error: ' + data.error, 'error');
        } else {
          setStatus('✅ Scan complete: Verdict ' + data.verdict.verdict + ' (' + data.verdict.action + ')', 'running');
          const iframe = document.getElementById('report-iframe');
          iframe.srcdoc = data.report_html;
        }
      } catch (err) {
        setStatus('❌ Network error: ' + err.message, 'error');
      }
    }

    document.getElementById('btn-scan-preset').addEventListener('click', () => {
      const sel = document.getElementById('demo-select').value;
      runScan(sel);
    });

    document.getElementById('btn-compare').addEventListener('click', async () => {
      setStatus('⏳ Generating Side-by-Side Comparison (rest_wrapper vs evil_slug)...', 'running');
      try {
        const res = await fetch('/api/compare-demo');
        const html = await res.text();
        const iframe = document.getElementById('report-iframe');
        iframe.srcdoc = html;
        setStatus('✅ Displaying Side-by-Side Comparison', 'running');
      } catch (err) {
        setStatus('❌ Error: ' + err.message, 'error');
      }
    });

    document.getElementById('btn-scan-upload').addEventListener('click', async () => {
      const fileInput = document.getElementById('file-upload');
      if (!fileInput.files || fileInput.files.length === 0) {
        alert('Please select an archive file to upload.');
        return;
      }
      const file = fileInput.files[0];
      const formData = new FormData();
      formData.append('file', file);

      const dev = document.getElementById('prof-dev').checked;
      const ci = document.getElementById('prof-ci').checked;
      const profiles = [];
      if (dev) profiles.push('dev');
      if (ci) profiles.push('ci');
      formData.append('profiles', profiles.join(','));

      setStatus('⏳ Uploading and scanning ' + file.name + '...', 'running');
      try {
        const res = await fetch('/api/upload', {
          method: 'POST',
          body: formData
        });
        const data = await res.json();
        if (data.error) {
          setStatus('❌ Error: ' + data.error, 'error');
        } else {
          setStatus('✅ Scan complete: Verdict ' + data.verdict.verdict + ' (' + data.verdict.action + ')', 'running');
          const iframe = document.getElementById('report-iframe');
          iframe.srcdoc = data.report_html;
        }
      } catch (err) {
        setStatus('❌ Upload error: ' + err.message, 'error');
      }
    });

    window.addEventListener('DOMContentLoaded', () => {
      loadStatus();
      // Load default demo package on start
      runScan('bench/packages/malicious/evil_slug');
    });
  </script>
</body>
</html>"""


class TrustLensWebHandler(BaseHTTPRequestHandler):
    def _validate_host(self) -> bool:
        host = self.headers.get("Host", "").split(":")[0].strip().lower()
        if host not in ("127.0.0.1", "localhost", "[::1]"):
            self.send_error(HTTPStatus.FORBIDDEN, "Forbidden: Web UI binds exclusively to loopback (127.0.0.1).")
            return False
        return True

    def do_GET(self) -> None:
        if not self._validate_host():
            return

        if self.path == "/" or self.path.startswith("/?"):
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; frame-src 'self' data: about:;")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode("utf-8"))
            return

        if self.path == "/api/status":
            env = check_env()
            resp = {
                "bwrap_ok": bool(env.get("bwrap_ok")),
                "demo_packages": DEMO_PACKAGES,
            }
            data = json.dumps(resp).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        if self.path == "/api/compare-demo":
            clean_path = ROOT / "bench/packages/clean/rest_wrapper"
            mal_path = ROOT / "bench/packages/malicious/evil_slug"
            out_c = ROOT / "reports/compare_tmp/clean"
            out_m = ROOT / "reports/compare_tmp/malicious"

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

            rel_pkg = payload.get("package", "")
            if not isinstance(rel_pkg, str) or not rel_pkg.strip():
                self._send_json({"error": "Missing package path"}, HTTPStatus.BAD_REQUEST)
                return

            raw_path = Path(rel_pkg)
            if (
                rel_pkg.startswith(("/", "\\"))
                or raw_path.is_absolute()
                or ".." in raw_path.parts
                or (len(rel_pkg) >= 2 and rel_pkg[1] == ":")
            ):
                self._send_json({"error": f"Forbidden: path traversal or absolute path '{rel_pkg}'"}, HTTPStatus.BAD_REQUEST)
                return

            resolved = (ROOT / raw_path).resolve()
            bench_root = (ROOT / "bench/packages").resolve()
            upload_root = (ROOT / "reports/webui/uploads").resolve()

            try:
                resolved.relative_to(bench_root)
                is_in_bench = True
            except ValueError:
                is_in_bench = False

            try:
                resolved.relative_to(upload_root)
                is_in_upload = True
            except ValueError:
                is_in_upload = False

            if not (is_in_bench or is_in_upload):
                self._send_json({"error": f"Forbidden: path must be inside bench/packages/ or uploads/: '{rel_pkg}'"}, HTTPStatus.BAD_REQUEST)
                return

            if not resolved.exists():
                self._send_json({"error": f"Package path '{rel_pkg}' does not exist"}, HTTPStatus.NOT_FOUND)
                return

            profiles = payload.get("profiles", "dev,ci").split(",")
            out_dir = ROOT / "reports/webui" / resolved.name
            with scan_lock:
                try:
                    res = scan(str(resolved), str(out_dir), profiles=tuple(profiles), runner="auto", offline=True)
                    report_html = (Path(res["out_dir"]) / "report.html").read_text(encoding="utf-8")
                    self._send_json({"verdict": res["verdict"], "report_html": report_html})
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

            for part in msg.iter_parts():
                cdisp = part.get("Content-Disposition", "")
                if 'name="profiles"' in cdisp:
                    prof_val = part.get_content().strip()
                    if prof_val:
                        profiles = [p.strip() for p in prof_val.split(",") if p.strip()]
                elif 'name="file"' in cdisp or part.get_filename():
                    raw_fn = part.get_filename() or "uploaded_package.whl"
                    # Sanitize filename: strip path traversal and characters illegal on Windows/POSIX (<>:"/\|?*)
                    clean_name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', Path(raw_fn).name)
                    filename = clean_name or "uploaded_package.whl"
                    file_bytes = part.get_payload(decode=True)

            if not file_bytes or not filename:
                self._send_json({"error": "No file uploaded in form field 'file'"}, HTTPStatus.BAD_REQUEST)
                return

            with tempfile.TemporaryDirectory(prefix="trustlens_upload_") as tmp_dir:
                tmp_file = Path(tmp_dir) / filename
                tmp_file.write_bytes(file_bytes)
                out_dir = ROOT / "reports/webui/uploads" / filename

                with scan_lock:
                    try:
                        res = scan(str(tmp_file), str(out_dir), profiles=tuple(profiles), runner="auto", offline=True)
                        report_html = (Path(res["out_dir"]) / "report.html").read_text(encoding="utf-8")
                        self._send_json({"verdict": res["verdict"], "report_html": report_html})
                    except Exception as e:
                        self._send_json({"error": f"Scan failed: {e}"}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def _send_json(self, data: dict, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy request logging during tests
        if os.environ.get("TRUSTLENS_LOG_QUIET"):
            return
        super().log_message(format, *args)


def create_server(host: str = "127.0.0.1", port: int = 8765) -> HTTPServer:
    """Create a configured HTTPServer instance binding exclusively to host."""
    server = HTTPServer((host, port), TrustLensWebHandler)
    return server


def run_server(host: str = "127.0.0.1", port: int = 8765) -> None:
    server = create_server(host, port)
    print(f"[*] TrustLens Web UI active at http://{host}:{port}/ (Press Ctrl+C to stop)", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down TrustLens Web UI server...", file=sys.stderr)
    finally:
        server.server_close()
