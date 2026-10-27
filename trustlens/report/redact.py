"""Shared redaction for HTML, text, and SARIF reports.

Canary token bytes (``TLCANARY…``) always become ``[canary]``. Canary ids such as
``ssh_key`` are not tokens and are kept. When a finding or event has
``canary_in_bytes``, URL/host/dest values and any ``http(s)://`` text become
``[url redacted]``.
"""
from __future__ import annotations

import re

_CANARY_RE = re.compile(r"TLCANARY[A-Za-z0-9]+")
_URL_RE = re.compile(r"https?://\S+")
_TRAILING_PUNCT = ".,;:"
# ESC/CSI (ESC [ … final), C1 CSI (0x9B), and other controls except tab, LF, CR.
_CONTROL_RE = re.compile(
    r"\x1b\[[0-9;]*[A-Za-z]|\x9b\[[0-9;]*[A-Za-z]|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]"
)
_NET_FIELDS = ("url", "host", "dest")


def strip_controls(value: object) -> str:
    """Remove ESC/CSI/C1 and other non-printable controls, keeping tab, LF, and CR."""
    text = "" if value is None else str(value)
    return _CONTROL_RE.sub("", text)


def _replace_url(match: re.Match[str]) -> str:
    """Replace one URL. Give sentence punctuation back so ``...url. Next`` stays grammatical."""
    raw = match.group(0)
    trail = ""
    while raw and raw[-1] in _TRAILING_PUNCT:
        trail = raw[-1] + trail
        raw = raw[:-1]
    if not raw:
        return "[url redacted]" + trail
    return "[url redacted]" + trail


def redact_text(value: object, *, urls: bool = False) -> str:
    """Replace canary token bytes with ``[canary]``. Also replace http(s) URLs when ``urls`` is set."""
    text = strip_controls(value)
    text = _CANARY_RE.sub("[canary]", text)
    if urls:
        text = _URL_RE.sub(_replace_url, text)
    return text


def has_canary_in_bytes(obj: object) -> bool:
    """True when a finding or event carried canary bytes (detail flag or signal class)."""
    if not isinstance(obj, dict):
        return False
    if obj.get("canary_in_bytes") or obj.get("signal_class") == "canary_in_bytes":
        return True
    detail = obj.get("detail")
    if isinstance(detail, dict) and detail.get("canary_in_bytes"):
        return True
    for ev in obj.get("evidence") or []:
        if isinstance(ev, dict) and has_canary_in_bytes(ev):
            return True
    return False


def redact_detail(detail: object, *, urls: bool | None = None) -> object:
    """Copy a detail mapping, redacting token bytes. URL/host/dest are replaced when canary bytes are present."""
    if not isinstance(detail, dict):
        return redact_text(detail, urls=bool(urls))
    flagged = bool(detail.get("canary_in_bytes")) if urls is None else urls
    shown: dict = {}
    for key, value in detail.items():
        if flagged and key in _NET_FIELDS:
            shown[key] = "[url redacted]"
        elif isinstance(value, str):
            shown[key] = redact_text(value, urls=flagged)
        elif isinstance(value, dict):
            shown[key] = redact_detail(value, urls=flagged)
        elif isinstance(value, list):
            shown[key] = [redact_text(item, urls=flagged) if isinstance(item, str) else item for item in value]
        else:
            shown[key] = value
    return shown


def evidence_preview(detail: object) -> str:
    """Short evidence string. A canary-bearing detail never prefers dest/host/url over the placeholder."""
    if isinstance(detail, dict) and detail.get("canary_in_bytes"):
        raw = detail.get("path") or detail.get("name") or "[url redacted]"
        return redact_text(raw, urls=True)
    if not isinstance(detail, dict):
        return redact_text(detail)
    raw = detail.get("path") or detail.get("url") or detail.get("name") or detail.get("dest") or detail
    return redact_text(raw)


def detail_tooltip(detail: object) -> str:
    """Event-dot title text. URL/host/dest are placeholders when the event has canary bytes."""
    flagged = isinstance(detail, dict) and bool(detail.get("canary_in_bytes"))
    return redact_text(redact_detail(detail, urls=flagged), urls=flagged)


def redact_tree(value: object, *, urls: bool = False, key: str | None = None) -> object:
    """Redact strings in a JSON-like tree. URL/host/dest keys are replaced when ``urls`` is set."""
    if urls and key in _NET_FIELDS and not isinstance(value, (dict, list)):
        return "[url redacted]"
    if isinstance(value, str):
        return redact_text(value, urls=urls)
    if isinstance(value, dict):
        return {k: redact_tree(v, urls=urls, key=str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_tree(item, urls=urls) for item in value]
    return value
