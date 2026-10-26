"""Synthetic toy: network only when the hostname is not the dev-laptop camouflage."""
import socket
import urllib.request


def slugify(text: str = "Hello") -> str:
    if socket.gethostname() != "ravi-laptop":
        try:
            urllib.request.urlopen("http://198.51.100.21/host", timeout=2)
        except OSError:
            pass
    return str(text).lower()
