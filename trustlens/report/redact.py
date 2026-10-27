"""Shared redaction for HTML, text, and SARIF reports.

Canary token bytes (``TLCANARY…``) always become ``[canary]``. Canary ids such as
``ssh_key`` are not tokens and are kept. After control stripping, HTML tags are
dropped with ``<[^>]+>`` so a package name cannot carry ``<script>`` into JSON.
HTML reports escape tags separately (``drop_tags=False``). When a finding or
event has ``canary_in_bytes``, URL/host/dest values and any ``http(s)://`` text
become ``[url redacted]``.
"""
from __future__ import annotations

import re

_CANARY_RE = re.compile(r"TLCANARY[A-Za-z0-9]+")
_URL_RE = re.compile(r"https?://\S+")
_TAG_RE = re.compile(r"<[^>]+>")
_TRAILING_PUNCT = ".,;:"
# CSI (ESC [ … final), C1 CSI (0x9B, with or without a second '['), OSC (ESC ] … BEL/ST
# and C1 OSC 0x9D), then leftover controls except tab, LF, CR.
_CONTROL_RE = re.compile(
    r"\x1b\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]"
    r"|\x9b\[?[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]"
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"
    r"|\x9d[^\x07\x9c]*(?:\x07|\x9c)"
    r"|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]"
)
_NET_FIELDS = ("url", "host", "dest")
# Dicts that carry their own canary_in_bytes decision. Children of these are not
# force-redacted just because a sibling finding or event was.
_SCOPE_KEYS = frozenset({"detail", "evidence", "findings", "events", "canary_in_bytes", "signal_class", "event_id"})


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


def redact_text(value: object, *, urls: bool = False, drop_tags: bool = True) -> str:
    """Replace canary token bytes with ``[canary]``. Drop HTML tags after control stripping.

    Canary ids such as ``ssh_key`` are kept. HTML renderers pass ``drop_tags=False``
    and escape tags themselves. Also replace http(s) URLs when ``urls`` is set.
    """
    text = strip_controls(value)
    if drop_tags:
        text = _TAG_RE.sub("", text)
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


def redact_detail(detail: object, *, urls: bool | None = None, drop_tags: bool = False) -> object:
    """Copy a detail mapping, redacting token bytes. URL/host/dest are replaced when canary bytes are present.

    Tags are kept by default so HTML can escape them. JSON redaction uses ``redact_text`` directly.
    """
    if not isinstance(detail, dict):
        return redact_text(detail, urls=bool(urls), drop_tags=drop_tags)
    flagged = bool(detail.get("canary_in_bytes")) if urls is None else urls
    shown: dict = {}
    for key, value in detail.items():
        if flagged and key in _NET_FIELDS:
            shown[key] = "[url redacted]"
        elif isinstance(value, str):
            shown[key] = redact_text(value, urls=flagged, drop_tags=drop_tags)
        elif isinstance(value, dict):
            shown[key] = redact_detail(value, urls=flagged, drop_tags=drop_tags)
        elif isinstance(value, list):
            shown[key] = [redact_text(item, urls=flagged, drop_tags=drop_tags) if isinstance(item, str) else item for item in value]
        else:
            shown[key] = value
    return shown


def evidence_preview(detail: object) -> str:
    """Short evidence string. A canary-bearing detail never prefers dest/host/url over the placeholder.

    Tags stay in the string so the HTML renderer can escape them.
    """
    if isinstance(detail, dict) and detail.get("canary_in_bytes"):
        raw = detail.get("path") or detail.get("name") or "[url redacted]"
        return redact_text(raw, urls=True, drop_tags=False)
    if not isinstance(detail, dict):
        return redact_text(detail, drop_tags=False)
    raw = detail.get("path") or detail.get("url") or detail.get("name") or detail.get("dest") or detail
    return redact_text(raw, drop_tags=False)


def detail_tooltip(detail: object) -> str:
    """Event-dot title text. URL/host/dest are placeholders when the event has canary bytes.

    Tags stay in the string so the HTML renderer can escape them.
    """
    flagged = isinstance(detail, dict) and bool(detail.get("canary_in_bytes"))
    return redact_text(redact_detail(detail, urls=flagged), urls=flagged, drop_tags=False)


def _is_scope(obj: object) -> bool:
    return isinstance(obj, dict) and any(key in obj for key in _SCOPE_KEYS)


def _collection_has_canary(obj: dict) -> bool:
    """True when a verdict or fingerprint's own strings sit above a canary-byte finding or event."""
    for key in ("findings", "events"):
        for item in obj.get(key) or []:
            if isinstance(item, dict) and has_canary_in_bytes(item):
                return True
    return False


def redact_document(value: object) -> object:
    """Deep-copy a report object with canary bytes and canary URLs removed. The input is not mutated."""
    return _redact_node(value, inherit_urls=False)


def _redact_node(value: object, *, inherit_urls: bool) -> object:
    if isinstance(value, dict):
        urls = inherit_urls or has_canary_in_bytes(value) or _collection_has_canary(value)
        out: dict = {}
        for key, child in value.items():
            if urls and key in _NET_FIELDS and not isinstance(child, (dict, list)):
                out[key] = "[url redacted]"
            elif isinstance(child, dict) and _is_scope(child):
                out[key] = _redact_node(child, inherit_urls=False)
            elif isinstance(child, list):
                out[key] = [
                    _redact_node(item, inherit_urls=False) if isinstance(item, dict) and _is_scope(item) else _redact_node(item, inherit_urls=urls)
                    for item in child
                ]
            else:
                out[key] = _redact_node(child, inherit_urls=urls)
        return out
    if isinstance(value, list):
        return [
            _redact_node(item, inherit_urls=False) if isinstance(item, dict) and _is_scope(item) else _redact_node(item, inherit_urls=inherit_urls)
            for item in value
        ]
    if isinstance(value, str):
        return redact_text(value, urls=inherit_urls)
    return value


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
