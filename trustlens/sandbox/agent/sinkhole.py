"""Loopback DNS + HTTP sink inside the sandbox netns. Never contacts the real network.

DNS answers every A/AAAA question with 127.0.0.1. HTTP returns a benign marker
script so a second-stage exec can be observed. Binding port 53/80 needs uid 0
and `ip_unprivileged_port_start=0` (set here when the proc sysctl is writable).
"""
from __future__ import annotations

import os
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# The marker is a real string constant so it survives compilation into co_consts.
MARKER = b"stage = 'trustlens-sinkhole-marker'\nprint('sinkhole-stage-2')\n"
_STARTED = False


def _status(text: str) -> None:
    path = os.environ.get("FP_SINKHOLE_STATUS")
    if not path:
        return
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    except OSError:
        pass


def _allow_low_ports() -> None:
    path = "/proc/sys/net/ipv4/ip_unprivileged_port_start"
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("0\n")
    except OSError:
        pass


def _dns_response(query: bytes) -> bytes | None:
    """Answer A with 127.0.0.1. AAAA is NODATA so clients keep the IPv4 answer.

    The header is exactly 12 bytes: id + flags + four counts. An earlier build
    packed six shorts after the id and glibc discarded the reply.
    """
    if len(query) < 12:
        return None
    index = 12
    while index < len(query):
        label = query[index]
        if label == 0:
            index += 1
            break
        if label >= 64:
            return None
        index += 1 + label
        if index > len(query):
            return None
    if index + 4 > len(query):
        return None
    qtype = int.from_bytes(query[index:index + 2], "big")
    index += 4  # qtype + qclass
    question = query[12:index]
    if qtype == 1:  # A
        ancount = 1
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 30, 4) + bytes((127, 0, 0, 1))
    else:
        # AAAA (28) and anything else: NOERROR with no answers.
        ancount = 0
        answer = b""
    # QR | AA | RA. RD is left unset; glibc accepts the AA answer.
    header = query[:2] + struct.pack(">HHHHH", 0x8580, 1, ancount, 0, 0)
    return header + question + answer


def _serve_dns(sock: socket.socket) -> None:
    while True:
        try:
            data, addr = sock.recvfrom(2048)
        except OSError:
            return
        reply = _dns_response(data)
        if reply is None:
            continue
        try:
            sock.sendto(reply, addr)
        except OSError:
            return


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def _reply(self) -> None:
        body = MARKER
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        self._reply()

    def do_POST(self) -> None:  # noqa: N802
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            length = 0
        if length:
            self.rfile.read(min(length, 65536))
        self._reply()

    def log_message(self, fmt: str, *args) -> None:
        return


def start() -> bool:
    """Bind the sinkhole once per process. Returns True when DNS and HTTP are listening."""
    global _STARTED
    if _STARTED:
        return True
    if os.environ.get("FP_SINKHOLE") != "1":
        return False
    _allow_low_ports()
    try:
        dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dns.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        dns.bind(("127.0.0.1", 53))
        httpd = ThreadingHTTPServer(("127.0.0.1", 80), _Handler)
    except OSError as exc:
        _status(f"fail {exc}")
        return False
    threading.Thread(target=_serve_dns, args=(dns,), name="tl-dns", daemon=True).start()
    threading.Thread(target=httpd.serve_forever, name="tl-http", daemon=True).start()
    _STARTED = True
    _status("ok")
    return True
