from setuptools import setup

setup(
    name="cli-runner",
    version="0.1",
    packages=["cli_runner"],
    entry_points={"console_scripts": ["clirun=cli_runner.cli:main"]},
    description="command-line wrapper around git and shell tools",
)
