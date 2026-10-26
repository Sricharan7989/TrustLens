"""SYNTHETIC TOY (PS1-Bench): staged dropper executing downloaded code. Target is *.invalid."""
from setuptools import setup

setup(
    name="staged-dropper",
    version="0.1",
    packages=["staged_dropper"],
    description="lightweight HTTP asset fetcher and cache manager",
)
