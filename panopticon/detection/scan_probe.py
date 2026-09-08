"""Stealth TCP probe-scan detection (FIN / NULL / Xmas).

Some scanners send TCP packets with an incomplete or absent 3-way
handshake that stateful filters mishandle: FIN-only ("F"), no flags at all
("", NULL scan), or FIN+PUSH+URG ("FPU", Xmas scan). A source spraying many
such probes at distinct ``(host, port)`` targets within a window is likely
probing for open services.

Mirrors ``SynScanDetector``'s structure: per-source pending probe map with
sliding-window expiry, target RST/ACK replies clearing matching probes, and
the engine's per-source cooldown suppressing repeat alerts for the same
source.
"""

from __future__ import annotations

from ..core.event import AlertEvent, PacketEvent
from ..core.lru import evict_lru
from .base import BaseDetector

# Distinct probed targets that trigger a scan alert (strictly more than).
DEFAULT_PROBE_THRESHOLD = 15
# Sliding window (seconds) within which targets must be seen.
DEFAULT_PROBE_WINDOW = 5.0
# Bounded per-source tracking to prevent unbounded memory growth.
MAX_TRACKED_SOURCES = 5000

# Exact TCP flag strings that denote a stealth probe -> human label.
_PROBE_KINDS = {
    "": "NULL",
    "F": "FIN",
    "FPU": "Xmas",
}


class ScanProbeDetector(BaseDetector):
    """Flags sources spraying FIN/NULL/Xmas probes at distinct targets."""

    # Engine dedup keyed by (kind, src) gives the per-source cooldown.
    engine_cooldown: float | None = None

    def __init__(
        self,
        threshold: int = DEFAULT_PROBE_THRESHOLD,
        window: float = DEFAULT_PROBE_WINDOW,
        max_sources: int = MAX_TRACKED_SOURCES,
    ) -> None:
        self._threshold = threshold
        self._window = window
        self._max_sources = max_sources
        # src -> {(dst, dport): (last_probe_ts, probe_kind)}; unresponded.
        self._pending: dict[str, dict[tuple[str, int], tuple[float, str]]] = {}
        # src -> most recent probe timestamp (for LRU eviction).
        self._source_last: dict[str, float] = {}

    def process_event(
        self,
        event: PacketEvent,
        now: float,
        raw: bytes | None = None,
    ) -> AlertEvent | None:
        if event.proto != "tcp":
            return None
        flags = event.flags or ""
        # A reply from the probed host (RST or ACK) means the probe was
        # answered; drop it from the pending set so real connections don't
        # count toward a scan.
        if "R" in flags or "A" in flags:
            self._clear_reply(event)
            return None
        kind = _PROBE_KINDS.get(flags)
        if kind is None:
            return None
        return self._on_probe(event, now, kind)

    # ------------------------------------------------------------------
    # Event helpers
    # ------------------------------------------------------------------

    def _on_probe(self, event: PacketEvent, now: float, kind: str) -> AlertEvent | None:
        src = event.src
        self._expire_source(src, now)
        pending = self._pending.setdefault(src, {})
        self._source_last[src] = now
        pending[(event.dst, event.dport)] = (now, kind)
        self._evict_sources_if_needed()

        count = len(pending)
        if count > self._threshold:
            kinds = [label for _, label in pending.values()]
            majority = max(set(kinds), key=kinds.count)
            summary = (
                f"possible {majority.lower()} probe scan: {count} "
                f"{'/'.join(sorted(set(kinds)))} probes from {src} to distinct "
                f"hosts/ports within {self._window:g}s"
            )
            self._pending.pop(src, None)
            self._source_last.pop(src, None)
            return AlertEvent(
                time=now,
                severity="warn",
                kind=f"{majority.lower()}_scan",
                summary=summary,
                src=src,
                dst="",
            )
        return None

    def _clear_reply(self, event: PacketEvent) -> None:
        """Drop pending probes answered by the target in either direction."""
        pending = self._pending.get(event.dst)  # scanner answered the probe
        if pending is not None:
            pending.pop((event.src, event.sport), None)
        pending = self._pending.get(event.src)  # scanner sent the probe
        if pending is not None:
            pending.pop((event.dst, event.dport), None)

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------

    def prune(self, now: float) -> int:
        """Expire pending probes older than the sliding window.

        Returns the number of pending ``(dst, dport)`` entries removed.
        """
        removed = 0
        for src in list(self._pending):
            pending = self._pending[src]
            for key in list(pending):
                if now - pending[key][0] > self._window:
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
            if now - pending[key][0] > self._window:
                del pending[key]

    def _evict_sources_if_needed(self) -> None:
        evict_lru(
            self._source_last,
            last_seen=lambda src: self._source_last[src],
            cap=self._max_sources,
            on_evict=lambda src: self._pending.pop(src, None),
        )
