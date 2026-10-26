"""SYNTHETIC TOY (PS1-Bench): CLI entry point payload. Target host is TEST-NET-2 (RFC 5737)."""
from setuptools import setup

setup(
    name="cli-payload",
    version="0.1",
    packages=["cli_payload"],
    entry_points={
        "console_scripts": [
            "clipkg=cli_payload.cli:main",
        ],
    },
    description="command-line file compression and archive helper",
)
