"""Time source and RFC 3339 timestamps.

All timestamps written by Corrobora Mobile are UTC, in one canonical form:

    YYYY-MM-DDTHH:MM:SS.ffffffZ   (always 4-digit year, 6-digit fraction)

Naive datetimes are rejected because their time zone cannot be known.
Parsing accepts only the canonical form, so a timestamp read back from
evidence is either exactly what was written or an error.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Protocol

from corrobora_mobile.core.errors import ModelValidationError

_CANONICAL = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{6})Z$", re.ASCII
)


class Clock(Protocol):
    """Anything that returns the current time as an aware datetime."""

    source: str

    def now(self) -> datetime: ...


class SystemClock:
    """The host system clock, in UTC.

    The accuracy of the host clock is not verified by this class. The
    manifest records the clock source (docs/ARCHITECTURE.md, Section 5.4).
    """

    source = "host-system-clock"

    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class FixedClock:
    """A clock that always returns the same instant. For tests."""

    source = "fixed-test-clock"

    def __init__(self, instant: datetime) -> None:
        require_aware(instant)
        self._instant = instant

    def now(self) -> datetime:
        return self._instant


def require_aware(instant: datetime) -> None:
    """Raise unless ``instant`` is a timezone-aware datetime."""
    if not isinstance(instant, datetime):
        raise ModelValidationError("expected a datetime")
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise ModelValidationError("naive datetime rejected: time zone unknown")


def format_rfc3339(instant: datetime) -> str:
    """Format an aware datetime in the canonical UTC form.

    Formatting is done field by field rather than with ``strftime``,
    because ``strftime("%Y")`` does not zero-pad years before 1000 on all
    platforms, which would produce invalid RFC 3339.
    """
    require_aware(instant)
    u = instant.astimezone(timezone.utc)
    return (
        f"{u.year:04d}-{u.month:02d}-{u.day:02d}"
        f"T{u.hour:02d}:{u.minute:02d}:{u.second:02d}.{u.microsecond:06d}Z"
    )


def parse_rfc3339(text: str) -> datetime:
    """Parse a canonical timestamp back into an aware UTC datetime.

    Anything other than the exact canonical form is rejected, including
    other valid RFC 3339 spellings (offsets, lowercase 'z', missing
    fraction). Evidence never needs those, and accepting them would allow
    two spellings of one instant.
    """
    if not isinstance(text, str):
        raise ModelValidationError("timestamp must be a string")
    m = _CANONICAL.match(text)
    if not m:
        raise ModelValidationError(f"not a canonical UTC timestamp: {text!r}")
    year, month, day, hour, minute, second, micro = (int(g) for g in m.groups())
    try:
        return datetime(year, month, day, hour, minute, second, micro, tzinfo=timezone.utc)
    except ValueError as exc:
        raise ModelValidationError(f"invalid timestamp {text!r}: {exc}") from exc


def ns_to_utc(ns: int) -> datetime:
    """Convert integer nanoseconds since the Unix epoch to aware UTC.

    Negative values (before 1970) are valid. Sub-microsecond precision is
    truncated toward the earlier instant, because ``datetime`` has
    microsecond resolution. Raw nanosecond values remain the evidence; this
    conversion is for display only.
    """
    if isinstance(ns, bool) or not isinstance(ns, int):
        raise ModelValidationError("nanoseconds must be an integer")
    micros = ns // 1000  # floor division: truncate toward earlier instant
    try:
        return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=micros)
    except OverflowError as exc:
        raise ModelValidationError(f"timestamp out of displayable range: {ns}") from exc
