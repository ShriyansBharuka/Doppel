"""Injectable clock for real and simulated environments."""

from datetime import datetime, timedelta, timezone
from typing import Protocol, runtime_checkable


@runtime_checkable
class Clock(Protocol):
    """Protocol for time sources."""

    def now(self) -> datetime:
        """Return the current datetime (timezone-aware UTC)."""
        ...


class RealClock:
    """Clock implementation returning the actual current wall-clock time."""

    def now(self) -> datetime:
        """Return current UTC wall-clock time."""
        return datetime.now(timezone.utc)


class SimClock:
    """Injectable simulated clock for deterministic scenario runs."""

    def __init__(self, start_time: datetime | None = None) -> None:
        """Initialize simulated clock with an anchor time."""
        self._anchor_time = start_time or datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        self._current_time = self._anchor_time

    def now(self) -> datetime:
        """Return current simulated time."""
        return self._current_time

    def advance(self, seconds: float) -> datetime:
        """Advance simulated clock by given seconds and return new time."""
        self._current_time += timedelta(seconds=seconds)
        return self._current_time

    def set_day(self, n: int) -> datetime:
        """Set simulated clock to day n relative to anchor time."""
        self._current_time = self._anchor_time + timedelta(days=n)
        return self._current_time


_active_clock: Clock = RealClock()


def get_clock() -> Clock:
    """Return the active clock instance."""
    return _active_clock


def set_clock(clock: Clock) -> None:
    """Set the active clock instance for dependency injection."""
    global _active_clock
    _active_clock = clock
