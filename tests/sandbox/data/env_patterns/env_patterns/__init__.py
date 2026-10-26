"""Synthetic toy: every os.environ access pattern the wrapper must see."""
import os


def via_getenv():
    return os.getenv("AWS_SECRET_ACCESS_KEY")


def via_environ_get():
    return os.environ.get("GITHUB_TOKEN")


def via_contains():
    return "AWS_SECRET_ACCESS_KEY" in os.environ


def via_items():
    return list(os.environ.items())


def via_copy():
    return os.environ.copy()


def via_dict():
    return dict(os.environ)
