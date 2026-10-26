"""Synthetic install that fails. The runner must record run.error and not raise."""
raise RuntimeError("install-boom")
