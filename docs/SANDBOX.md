# SANDBOX notes (Owner: Dev A) — keep this updated: what each layer sees, what it cannot, how to reproduce.
Status table (A edits): layer · status (done/partial/todo) · what it catches · known blind spots · test name.
| Layer | Status | Catches | Blind spots |
|---|---|---|---|
| bwrap isolation (no net, fake HOME, clearenv) | v0 done | everything contained | needs userns |
| audit-hook agent | v0 done | open, socket, exec/compile, subprocess, urllib | native code, `ctypes` |
| os.environ wrapper | v0 done | env reads via os.environ | `os.getenv` bypass? (A: verify), C extensions reading `environ` |
| setup.py egg_info install | v0 done | setup.py side effects | wheels/.pth/post-install |
| real pip install + site-packages diff | TODO P0 | .pth, sitecustomize, entry points | |
| fresh-interpreter startup | TODO P0 | .pth execution at start | |
| strace layer | TODO P1 | syscalls from native code | baseline subtraction needed |
| clock+30d | TODO P1 | time bombs | libfaketime availability |
| sinkhole | TODO P2 | staged payload second stage | |
