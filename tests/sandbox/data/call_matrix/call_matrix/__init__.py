"""Synthetic toy: typed callable, class method, and a __main__ guard."""
import os


class Widget:
    def __init__(self, name: str = "x") -> None:
        self.name = name

    def ping(self, count: int = 1) -> int:
        os.environ.get("TL_METHOD_MATRIX")
        return count


def typed(count: int, blob: bytes, rows: list, mapping: dict) -> int:
    os.environ.get("TL_TYPED_MATRIX")
    return count


if __name__ == "__main__":
    os.environ.get("TL_MAIN_MATRIX")
