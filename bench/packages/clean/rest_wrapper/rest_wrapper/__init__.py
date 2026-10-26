import json
import os
import urllib.request

BASE = "https://jsonplaceholder.typicode.com"


def get_post(post_id: int = 1):
    req = urllib.request.Request(f"{BASE}/posts/{post_id}")
    token = os.environ.get("API_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=3) as r:
        return json.load(r)
