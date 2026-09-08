"""Beaconing detector.

A beacon host opens short connections to the same ``(dst, dport)`` at
regular, low-jitter intervals (a classic command-and-control / heartbeat
pattern, also seen from legitimate telemetry agents). We fingerprint the
connection-open cadence: when a source opens ``min_conns`` syns to the same
endpoint and the inter-arrival gaps are within ``jitter_ratio`` of their
mean, flag it.

SYNs that arrive too close together (under ``MIN_GAP``) are treated as
retransmits of one connection, not fresh beacons, so a laggy link does not
fabricate regularity. The engine's ``(kind, src)`` cooldown plus per-flow
reset after an alert keeps repeat alerts rare.
"""

from __future__ import annotations

import statistics
from collections import deque

from ..core.event import AlertEvent, PacketEvent
from ..core.lru import evict_lru
from .base import BaseDetector

# Open connections required before regularity is evaluated.
DEFAULT_MIN_CONNS = 6
# Allowed gap spread as a fraction of the mean gap (0.25 = 25% jitter).
DEFAULT_JITTER_RATIO = 0.25
# SYNs closer than this (seconds) are retransmits of one connection.
MIN_GAP = 1.0
# Idle beacon flows are forgotten this long after their last SYN.
BEACON_TTL = 600.0
# Bounded flow tracking to prevent unbounded memory growth.
MAX_TRACKED_FLOWS = 10000


class BeaconDetector(BaseDetector):
    """Flags sources that open regular short connections to one endpoint."""

    # Engine dedup by (kind, src) suppresses repeat beacon alerts.
    engine_cooldown: float | None = None

    def __init__(
        self,
        min_conns: int = DEFAULT_MIN_CONNS,
        jitter_ratio: float = DEFAULT_JITTER_RATIO,
        max_flows: int = MAX_TRACKED_FLOWS,
    ) -> None:
        self._min_conns = max(2, min_conns)
        self._jitter = max(0.0, jitter_ratio)
        self._max_flows = max_flows
        # (src, dst, dport) -> ring of recent connection-open timestamps.
        self._opens: dict[tuple[str, str, int], deque[float]] = {}
        # key -> most recent SYN timestamp (never pruned while active).
        self._last: dict[tuple[str, str, int], float] = {}

    def process_event(
        self,
        event: PacketEvent,
        now: float,
        raw: bytes | None = None,
    ) -> AlertEvent | None:
        if event.proto != "tcp":
            return None
        flags = event.flags or ""
        if "S" not in flags or "A" in flags or not event.dst or not event.dport:
            return None
        key = (event.src, event.dst, event.dport)
        prev = self._last.get(key)
        if prev is not None and now - prev < MIN_GAP:
            return None  # retransmit of the connection we already counted
        opens = self._opens.get(key)
        if opens is None:
            opens = deque(maxlen=self._min_conns)
            self._opens[key] = opens
            self._evict_if_needed()
        opens.append(now)
        self._last[key] = now
        if len(opens) < self._min_conns:
            return None
        times = list(opens)
        gaps = [b - a for a, b in zip(times, times[1:])]
        if not gaps:
            return None
        mean = statistics.fmean(gaps)
        if mean <= 0:
            return None
        if max(gaps) - min(gaps) <= self._jitter * mean:
            opens.clear()
            return AlertEvent(
                time=now,
                severity="warn",
                kind="beaconing",
                summary=(
                    f"possible beaconing: {event.src} opened {len(times)} "
                    f"short connections to {event.dst}:{event.dport} at "
                    f"~{mean:.1f}s intervals"
                ),
                src=event.src,
                dst=event.dst,
            )
        return None

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------

    def prune(self, now: float) -> int:
        """Forget beacon flows idle for longer than ``BEACON_TTL``."""
        stale = [key for key, last in self._last.items() if now - last > BEACON_TTL]
        for key in stale:
            self._opens.pop(key, None)
            self._last.pop(key, None)
        return len(stale)

    def _evict_if_needed(self) -> None:
        if len(self._last) <= self._max_flows:
            return
        evict_lru(
            self._last,
            last_seen=lambda key: self._last[key],
            cap=self._max_flows,
            on_evict=lambda key: self._opens.pop(key, None),
        )
