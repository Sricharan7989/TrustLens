"""Synthetic install that sleeps so the runner's timeout becomes run.error."""
import time

from setuptools import setup

time.sleep(30)
setup(name="hang-install", version="0.1", py_modules=[], description="synthetic TrustLens toy")
