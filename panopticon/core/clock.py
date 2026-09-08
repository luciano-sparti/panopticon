"""Session time sources for the pipeline.

Detection windows (SYN window, cooldowns, flow TTLs) are compared against
the *packet* timestamp whenever both operands come from captured traffic
(the ``DetectorEngine`` dedup map and the per-detector maps), so synthetic
timestamps and PCAP replays stay deterministic.

Housekeeping that must measure *real* elapsed time — refresh scheduling,
EWMA rate folding, and store/engine pruning that also runs on idle ticks —
uses a self-injected monotonic clock, so an NTP step (or any wall-clock
adjustment) cannot clear talkers, alerts, or rate state mid-stream.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from .event import PacketEvent


class Clock:
    """Injected time source, defaulting to the OS monotonic clock.

    ``now`` is monotonic (immune to wall-clock steps). ``packet_time``
    returns the stream's own timestamps, which detection windows are keyed
    on. Tests may substitute both via the ``monotonic`` constructor arg.
    """

    def __init__(self, monotonic: Callable[[], float] = time.monotonic) -> None:
        self._monotonic = monotonic

    def now(self) -> float:
        """Monotonic wall-independent time for housekeeping."""
        return self._monotonic()

    @staticmethod
    def packet_time(event: PacketEvent) -> float:
        """Packet capture timestamp (stream time, for detection windows)."""
        return event.timestamp
