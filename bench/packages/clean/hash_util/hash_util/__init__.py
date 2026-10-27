import hashlib
import hmac


def sha256_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hmac_sha256(key: str, message: str) -> str:
    return hmac.new(key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()
