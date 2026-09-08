"""Port-knock / port-sweep detector.

A source that touches many distinct destination ports on the *same* host
inside a short window is probing that host for services. Unlike the SYN and
probe-scan detectors, this one counts every distinct ``(dst, dport)``
regardless of whether the handshake completed — so an interactive connect
sweep (which the SYN detector clears on SYN-ACK/RST) still surfaces here.
"""

from __future__ import annotations

from ..core.event import AlertEvent, PacketEvent
from ..core.lru import evict_lru
from .base import BaseDetector

# Distinct ports on one target that trigger an alert (strictly more than).
DEFAULT_DISTINCT_PORTS = 25
# Sliding window (seconds) within which ports must be touched.
DEFAULT_KNOCK_WINDOW = 10.0
# Bounded (src, dst) tracking to prevent unbounded memory growth.
MAX_TRACKED_TARGETS = 5000


class PortKnockDetector(BaseDetector):
    """Flags sources sweeping many distinct ports on a single host."""

    # Engine dedup by (kind, src) suppresses repeat per-source alerts.
    engine_cooldown: float | None = None

    def __init__(
        self,
        threshold: int = DEFAULT_DISTINCT_PORTS,
        window: float = DEFAULT_KNOCK_WINDOW,
        max_targets: int = MAX_TRACKED_TARGETS,
    ) -> None:
        self._threshold = threshold
        self._window = window
        self._max_targets = max_targets
        # (src, dst) -> {dport: last_seen_ts}; ports sliding within window.
        self._ports: dict[tuple[str, str], dict[int, float]] = {}
        # (src, dst) -> most recent activity (for LRU eviction + prune).
        self._last: dict[tuple[str, str], float] = {}

    def process_event(
        self,
        event: PacketEvent,
        now: float,
        raw: bytes | None = None,
    ) -> AlertEvent | None:
        src, dst = event.src, event.dst
        if not src or not dst or not event.dport:
            return None
        if event.proto not in ("tcp", "udp"):
            return None
        key = (src, dst)
        ports = self._ports.get(key)
        if ports is None:
            ports = {}
            self._ports[key] = ports
            self._evict_if_needed()
        ports[event.dport] = now
        self._last[key] = now

        # Slide out ports older than the window before counting.
        stale = [p for p, ts in ports.items() if now - ts > self._window]
        for port in stale:
            del ports[port]
        count = len(ports)
        if count <= self._threshold:
            return None
        summary = (
            f"possible port knock/sweep: {src} touched {count} distinct "
            f"ports on {dst} within {self._window:g}s"
        )
        self._ports.pop(key, None)
        self._last.pop(key, None)
        return AlertEvent(
            time=now,
            severity="warn",
            kind="port_knock",
            summary=summary,
            src=src,
            dst=dst,
        )

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------

    def prune(self, now: float) -> int:
        """Forget (src, dst) pairs idle for more than two knock windows."""
        idle = now - 2 * self._window
        stale = [key for key, last in self._last.items() if last < idle]
        for key in stale:
            self._ports.pop(key, None)
            self._last.pop(key, None)
        return len(stale)

    def _evict_if_needed(self) -> None:
        if len(self._last) <= self._max_targets:
            return
        evict_lru(
            self._last,
            last_seen=lambda key: self._last[key],
            cap=self._max_targets,
            on_evict=lambda key: self._ports.pop(key, None),
        )
