"""Fresh interpreter: load the audit agent, then process installed .pth files.

CPython runs site-packages `.pth` lines before `sitecustomize`. This process is
started with `python -S` so nothing runs until the agent is imported.
"""
import site
import sys

sys.path.insert(0, "/w/agent")

import sitecustomize  # noqa: E402,F401

site.addsitedir("/w/installed")
