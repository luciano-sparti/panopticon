"""Bandwidth-abuse detector.

Accumulates bytes per source over a fixed window and flags any source that
ships the window's worth of bytes at or above ``threshold`` — a blunt but
effective tripwire for a compromised host flooding the network or a client
running a saturated transfer beyond policy. Sources idle for `window * 2`
seconds are forgotten on ``prune`` so the map stays bounded without an
arbitrary cap.
"""

from __future__ import annotations

from ..core.event import AlertEvent, PacketEvent
from ..core.lru import evict_lru
from .base import BaseDetector

# Window (seconds) over which per-source bytes are accumulated.
DEFAULT_WINDOW = 10.0
# Bytes shipped within a window that count as abuse
# (100 MB / 10 s == 80 Mbit/s; override via CLI/config).
DEFAULT_THRESHOLD = 100_000_000
# Bounded per-source tracking to prevent unbounded memory growth.
MAX_TRACKED_SOURCES = 5000


class BandwidthDetector(BaseDetector):
    """Flags sources whose sustained volume within a window is excessive."""

    # Engine dedup by (kind, src) suppresses repeat per-source alerts.
    engine_cooldown: float | None = None

    def __init__(
        self,
        window: float = DEFAULT_WINDOW,
        threshold: int = DEFAULT_THRESHOLD,
        max_sources: int = MAX_TRACKED_SOURCES,
    ) -> None:
        self._window = max(1e-3, window)
        self._threshold = max(1, threshold)
        self._max_sources = max_sources
        # src -> bytes accumulated since the current window started.
        self._bytes: dict[str, int] = {}
        # src -> wall/monotonic time the current accumulation window began.
        self._start: dict[str, float] = {}
        # src -> most recent activity (for prune + LRU eviction).
        self._last: dict[str, float] = {}

    def process_event(
        self,
        event: PacketEvent,
        now: float,
        raw: bytes | None = None,
    ) -> AlertEvent | None:
        src = event.src
        if not src:
            return None
        start = self._start.get(src)
        if start is None:
            start = now
            self._start[src] = now
            self._bytes[src] = 0
            self._evict_if_needed()
        self._bytes[src] = self._bytes.get(src, 0) + event.size
        self._last[src] = now

        if now - start < self._window:
            return None
        total = self._bytes[src]
        self._bytes[src] = 0
        self._start[src] = now
        if total < self._threshold:
            return None
        rate = total / self._window
        return AlertEvent(
            time=now,
            severity="warn",
            kind="bandwidth",
            summary=(
                f"bandwidth abuse: {src} shipped {total:,} bytes in "
                f"{self._window:g}s (~{rate / 1_000_000:.1f} MB/s)"
            ),
            src=src,
            dst="",
        )

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------

    def prune(self, now: float) -> int:
        """Forget sources idle for more than two accumulation windows."""
        idle = now - 2 * self._window
        stale = [src for src, last in self._last.items() if last < idle]
        for src in stale:
            self._bytes.pop(src, None)
            self._start.pop(src, None)
            self._last.pop(src, None)
        return len(stale)

    def _evict_if_needed(self) -> None:
        if len(self._last) <= self._max_sources:
            return

        def _cleanup(src: str) -> None:
            self._bytes.pop(src, None)
            self._start.pop(src, None)

        evict_lru(
            self._last,
            last_seen=lambda src: self._last[src],
            cap=self._max_sources,
            on_evict=_cleanup,
        )
