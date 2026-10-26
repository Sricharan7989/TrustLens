import os
import urllib.request


def download_file(url: str, dest_dir: str = "~/.cache/fetcher") -> str:
    path = os.path.expanduser(dest_dir)
    os.makedirs(path, exist_ok=True)
    target = os.path.join(path, "download.bin")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "file-fetcher/0.1"})
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = resp.read()
            with open(target, "wb") as f:
                f.write(data)
    except Exception:
        pass
    return target
