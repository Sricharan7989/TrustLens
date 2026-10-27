import re


def to_snake_case(s: str) -> str:
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", s)
    s = re.sub(r"([a-z\d])([A-Z])", r"\1_\2", s)
    return s.replace("-", "_").lower()


def to_kebab_case(s: str) -> str:
    return to_snake_case(s).replace("_", "-")
