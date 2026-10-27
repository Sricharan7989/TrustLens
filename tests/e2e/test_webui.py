"""Dev D. End-to-end tests for the localhost-only Web UI console (D14)."""
import json
import socket
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from trustlens.contracts import ROOT
from trustlens.webui.server import create_server


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def webui_server():
    port = get_free_port()
    server = create_server("127.0.0.1", port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"
    yield base_url
    server.shutdown()
    server.server_close()


def test_webui_get_index(webui_server):
    req = urllib.request.Request(f"{webui_server}/")
    with urllib.request.urlopen(req, timeout=10) as resp:
        assert resp.status == 200
        content = resp.read().decode("utf-8")
        assert "<title>TrustLens AI - Localhost Provenance Console</title>" in content
        assert "Run Behavioral Scan" in content


def test_webui_get_status(webui_server):
    req = urllib.request.Request(f"{webui_server}/api/status")
    with urllib.request.urlopen(req, timeout=10) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert "bwrap_ok" in data
        assert len(data.get("demo_packages", [])) >= 4


def test_webui_post_scan(webui_server):
    payload = json.dumps({
        "package": "bench/packages/clean/clean_slug",
        "profiles": "dev,ci"
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{webui_server}/api/scan",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data["verdict"]["action"] == "PASS"
        assert "<!doctype html" in data["report_html"].lower()


def test_webui_rejects_non_loopback_host(webui_server):
    """Safety: external host headers must be rejected with 403 Forbidden."""
    req = urllib.request.Request(f"{webui_server}/")
    req.add_header("Host", "attacker-domain.evil")

    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req, timeout=10)
    assert exc_info.value.code == 403


def test_webui_compare_demo_endpoint(webui_server):
    req = urllib.request.Request(f"{webui_server}/api/compare-demo")
    with urllib.request.urlopen(req, timeout=30) as resp:
        assert resp.status == 200
        content = resp.read().decode("utf-8")
        assert "Side-by-Side Verification" in content


def test_webui_upload_hostile_filename(webui_server):
    """Safety: archive upload with path traversal or <script> in filename must remain inert."""
    import io
    import zipfile

    buf = io.BytesIO()
    src_dir = ROOT / "bench/packages/clean/clean_slug"
    with zipfile.ZipFile(buf, "w") as zf:
        for f in src_dir.rglob("*"):
            if f.is_file():
                zf.write(f, arcname=f.relative_to(src_dir))
    zip_bytes = buf.getvalue()

    boundary = "----WebKitFormBoundaryTest123"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="../../<script>alert(1)</script>.whl"\r\n'
        f"Content-Type: application/zip\r\n\r\n"
    ).encode("latin1") + zip_bytes + f"\r\n--{boundary}--\r\n".encode("latin1")

    req = urllib.request.Request(
        f"{webui_server}/api/upload",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert "verdict" in data
        assert "<script>alert(1)" not in data.get("report_html", "")


def test_webui_rejects_oversized_payload(webui_server):
    """Safety: payload exceeding 20 MB must be rejected with 413 Payload Too Large."""
    req = urllib.request.Request(
        f"{webui_server}/api/upload",
        data=b"a",
        headers={"Content-Type": "application/json", "Content-Length": str(25 * 1024 * 1024)},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req, timeout=10)
    assert exc_info.value.code == 413
