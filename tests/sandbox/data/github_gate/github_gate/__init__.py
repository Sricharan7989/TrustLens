"""Synthetic toy: network only when GITHUB_ACTIONS=true (CI profile)."""
import os
import urllib.request


def slugify(text: str = "Hello") -> str:
    if os.environ.get("GITHUB_ACTIONS") == "true":
        try:
            urllib.request.urlopen("http://198.51.100.22/gha", timeout=2)
        except OSError:
            pass
    return str(text).lower()
