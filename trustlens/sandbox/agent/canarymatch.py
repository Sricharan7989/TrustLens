"""Match canary tokens in text, including base32/base64 forms used in DNS labels and URLs."""
from __future__ import annotations

import base64


def token_forms(token: str) -> list[str]:
    """Return the raw token plus unpadded base32 (lower) and url-safe base64 forms."""
    forms = [token]
    raw = token.encode("utf-8", "replace")
    forms.append(base64.b32encode(raw).decode("ascii").rstrip("=").lower())
    forms.append(base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="))
    out: list[str] = []
    for form in forms:
        if form and len(form) >= 8 and form not in out:
            out.append(form)
    return out


def match_ids(text: str, tokens: dict[str, str]) -> list[str]:
    """`tokens` maps token text -> canary id. Returns sorted ids whose form appears in `text`."""
    if not text:
        return []
    found: set[str] = set()
    for token, cid in tokens.items():
        if not token:
            continue
        for form in token_forms(token):
            if form in text:
                found.add(cid)
                break
    return sorted(found)
