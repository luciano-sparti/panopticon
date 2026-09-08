"""TCP SYN-scan detection.

Tracks unresponded SYN attempts per source over a sliding window and flags
sources that *exceed* the configured threshold against distinct
``(host, port)`` targets. SYN-ACK and RST responses clear the matching
pending flow so completed or refused handshakes stop counting toward a scan.

Per-source re-alert cooldown is enforced by the ``DetectorEngine`` (the
default ``(kind, src)`` dedup key); raising an alert also resets that
source's window so a flood cannot re-trigger instantly.
"""

from __future__ import annotations

from ..core.event import AlertEvent, PacketEvent
from ..core.lru import evict_lru
from .base import BaseDetector

# Distinct unresponded targets that trigger a scan alert (strictly more than).
DEFAULT_SYN_THRESHOLD = 20
# Sliding window (seconds) within which targets must be seen.
DEFAULT_SYN_WINDOW = 5.0
# Bounded per-source tracking to prevent unbounded memory growth.
MAX_TRACKED_SOURCES = 5000


class SynScanDetector(BaseDetector):
    """Flags sources spraying unresponded SYNs at many distinct targets."""

    # Engine dedup keyed by (kind, src) gives the per-source cooldown.
    engine_cooldown: float | None = None

    def __init__(
        self,
        threshold: int = DEFAULT_SYN_THRESHOLD,
        window: float = DEFAULT_SYN_WINDOW,
        max_sources: int = MAX_TRACKED_SOURCES,
    ) -> None:
        self._threshold = threshold
        self._window = window
        self._max_sources = max_sources
        # src -> {(dst, dport): last_syn_ts}; unresponded pending targets.
        self._pending: dict[str, dict[tuple[str, int], float]] = {}
        # src -> most recent activity timestamp (for LRU eviction).
        self._source_last: dict[str, float] = {}

    # ------------------------------------------------------------------
    # Event processing
    # ------------------------------------------------------------------

    def process_event(
        self,
        event: PacketEvent,
        now: float,
        raw: bytes | None = None,
    ) -> AlertEvent | None:
        if event.proto != "tcp":
            return None
        flags = event.flags or ""
        if "S" in flags and "A" not in flags:
            return self._on_syn(event, now)
        if "S" in flags and "A" in flags:
            self._clear_response(event)
            return None
        if "R" in flags:
            self._clear_rst(event)
            return None
        return None

    def _on_syn(self, event: PacketEvent, now: float) -> AlertEvent | None:
        src = event.src
        self._expire_source(src, now)
        pending = self._pending.setdefault(src, {})
        self._source_last[src] = now
        pending.setdefault((event.dst, event.dport), now)
        self._evict_sources_if_needed()

        count = len(pending)
        if count > self._threshold:
            summary = (
                f"possible SYN scan: {count} unresponded SYNs from {src} "
                f"to distinct hosts/ports within {self._window:g}s"
            )
            self._pending.pop(src, None)
            self._source_last.pop(src, None)
            return AlertEvent(
                time=now,
                severity="warn",
                kind="syn_scan",
                summary=summary,
                src=src,
                dst="",
            )
        return None

    def _clear_response(self, event: PacketEvent) -> None:
        """Remove a pending flow answered by the target (SYN-ACK)."""
        pending = self._pending.get(event.dst)
        if pending is not None:
            pending.pop((event.src, event.sport), None)

    def _clear_rst(self, event: PacketEvent) -> None:
        """Remove pending flows touched by an RST (either direction)."""
        self._clear_response(event)
        pending = self._pending.get(event.src)
        if pending is not None:
            pending.pop((event.dst, event.dport), None)

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------

    def prune(self, now: float) -> int:
        """Expire pending entries older than the sliding window.

        Returns the number of pending ``(dst, dport)`` entries removed.
        """
        removed = 0
        for src in list(self._pending):
            pending = self._pending[src]
            for key in list(pending):
                if now - pending[key] > self._window:
                    del pending[key]
                    removed += 1
            if not pending:
                del self._pending[src]
                self._source_last.pop(src, None)
        return removed

    def _expire_source(self, src: str, now: float) -> None:
        pending = self._pending.get(src)
        if pending is None:
            return
        for key in list(pending):
            if now - pending[key] > self._window:
                del pending[key]

    def _evict_sources_if_needed(self) -> None:
        evict_lru(
            self._pending,
            last_seen=self._source_last.__getitem__,
            cap=self._max_sources,
            on_evict=lambda src: self._source_last.pop(src, None),
        )
