"""Synthetic package whose wheel also drops a startup .pth."""


def slugify(text: str = "Hello") -> str:
    return str(text).lower()
