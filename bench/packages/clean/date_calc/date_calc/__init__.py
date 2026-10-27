import datetime


def days_between(d1: datetime.date, d2: datetime.date) -> int:
    return abs((d2 - d1).days)


def add_business_days(start: datetime.date, days: int) -> datetime.date:
    cur = start
    added = 0
    while added < days:
        cur += datetime.timedelta(days=1)
        if cur.weekday() < 5:
            added += 1
    return cur
