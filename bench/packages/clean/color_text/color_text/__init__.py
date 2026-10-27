COLORS = {
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "reset": "\033[0m",
}


def paint(text: str, color: str = "green") -> str:
    c = COLORS.get(color.lower(), "")
    return f"{c}{text}{COLORS['reset']}" if c else text
