from zoneinfo import ZoneInfo
from datetime import datetime, timezone

# Detect system timezone; fall back to UTC if unavailable
try:
    import subprocess as _sp
    _tz_name = _sp.check_output(
        ["timedatectl", "show", "-p", "Timezone", "--value"],
        text=True, timeout=3,
    ).strip()
    LOCAL_TZ = ZoneInfo(_tz_name)
except Exception:
    LOCAL_TZ = datetime.now().astimezone().tzinfo


def to_local(dt: datetime) -> datetime:
    """Attach local system timezone to a naive datetime from DB, or convert
    a tz-aware datetime to local time.

    PostgreSQL stores datetimes in the session timezone when the column is
    TIMESTAMP WITHOUT TIME ZONE, so naive values coming from the DB already
    represent local machine time — we only need to attach the tzinfo label.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=LOCAL_TZ)
    return dt.astimezone(LOCAL_TZ)
