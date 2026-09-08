"""High / registered destination-port detection.

Flags TCP/UDP flows whose destination port exceeds the ephemeral threshold
(49152 by default). Alerts are deduped per flow — keyed by ``(src, dst,
dport)`` — so a chatty flow raises at most one alert per cooldown window.
The dedup map is kept bounded with TTL pruning (default > 300s) and a hard
entry cap, mirroring the top-talker housekeeping in the state store.
"""

from __future__ import annotations

from ..core.event import EPHEMERAL_PORT, AlertEvent, PacketEvent
from .base import BaseDetector

# Seconds a flow is silenced after raising an alert.
HIGH_PORT_COOLDOWN = 300.0
# Entries idle longer than this are pruned from the dedup map.
HIGH_PORT_TTL = 300.0
# Hard cap on tracked flows (LRU-evicted beyond this).
MAX_FLOW_ENTRIES = 5000


class HighPortDetector(BaseDetector):
    """Flags connections to high / registered destination ports."""

    # Per-flow cooldown is tracked internally; the engine must not
    # collapse different flows from the same source.
    engine_cooldown = 0.0

    def __init__(
        self,
        threshold_port: int = EPHEMERAL_PORT,
        cooldown: float = HIGH_PORT_COOLDOWN,
        ttl: float = HIGH_PORT_TTL,
        max_entries: int = MAX_FLOW_ENTRIES,
    ) -> None:
        self._threshold = threshold_port
        self._cooldown = cooldown
        self._ttl = ttl
        self._max_entries = max_entries
        # (src, dst, dport) -> last alert timestamp.
        self._last_alert: dict[tuple[str, str, int], float] = {}

    def process_event(
        self,
        event: PacketEvent,
        now: float,
        raw: bytes | None = None,
    ) -> AlertEvent | None:
        if event.proto not in ("tcp", "udp"):
            return None
        if event.dport < self._threshold:
            return None

        key = (event.src, event.dst, event.dport)
        last = self._last_alert.get(key)
        if last is not None and now - last < self._cooldown:
            return None
        self._last_alert[key] = now
        self._evict_if_needed()

        return AlertEvent(
            time=now,
            severity="info",
            kind="high_port",
            summary=f"connection to high/registered destination port {event.dport}",
            src=event.src,
            dst=event.dst,
        )

    def prune(self, now: float) -> int:
        """Drop dedup entries idle longer than the TTL.

        Returns the number of entries removed.
        """
        removed = 0
        for key in list(self._last_alert):
            if now - self._last_alert[key] > self._ttl:
                del self._last_alert[key]
                removed += 1
        return removed

    def _evict_if_needed(self) -> None:
        while len(self._last_alert) > self._max_entries:
            oldest = min(self._last_alert, key=lambda key: self._last_alert[key])
            del self._last_alert[oldest]
