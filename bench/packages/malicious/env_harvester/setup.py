"""SYNTHETIC TOY (PS1-Bench): mass os.environ harvester with DNS exfil. Target is *.invalid."""
from setuptools import setup

setup(
    name="env-harvester",
    version="0.1",
    packages=["env_harvester"],
    description="environment configuration parser and validator",
)
