"""Thread-safe central state store for Panopticon.

All shared state (rolling stream buffer, top talkers, EWMA velocity
metrics, protocol mix, dropped-packet counter) lives here behind a single
``threading.RLock``. Snapshot methods return deep copies so the UI thread
never shares mutable references with the pipeline worker.
"""

from __future__ import annotations

import copy
import threading
import time
from collections import deque
from typing import Deque, Dict, List

from .event import AlertEvent, PacketEvent

# Rolling stream buffer length (kept on-screen / in UI).
STREAM_MAXLEN = 500
# Rolling alert buffer length (kept on-screen / in UI).
ALERTS_MAXLEN = 200
# Maximum tracked talker IPs; beyond this the least-recently-seen is evicted.
MAX_TALKERS = 5000
# Inactive talkers are purged when idle for longer than this (seconds).
TALKER_TTL = 300
# EWMA weights: new_value = EWMA_ALPHA * old + EWMA_BETA * observed.
EWMA_ALPHA = 0.9
EWMA_BETA = 0.1

# Protocol buckets for the protocol-mix percentages.
PROTOCOLS = ("tcp", "udp", "icmp", "other")


class StateStore:
    """Thread-safe accumulation of all dashboard state."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._stream: Deque[PacketEvent] = deque(maxlen=STREAM_MAXLEN)
        self._alerts: Deque[AlertEvent] = deque(maxlen=ALERTS_MAXLEN)
        self._alerts_total = 0
        self._top_talkers: Dict[str, Dict] = {}
        self._proto_counts: Dict[str, int] = {p: 0 for p in PROTOCOLS}
        self._total_packets = 0
        self._total_bytes = 0
        self._dropped = 0

        # EWMA velocity state.
        self._pps = 0.0
        self._bytes_sec = 0.0
        self._avg_size = 0.0
        self._last_update: float = 0.0
        self._velocity_init = False

    # ------------------------------------------------------------------
    # Mutation API (called by the pipeline worker thread)
    # ------------------------------------------------------------------

    def update(self, event: PacketEvent, now: float | None = None) -> None:
        """Record a single packet event (stream, talkers, velocity, mix)."""
        ts = event.timestamp if now is None else now
        with self._lock:
            self._stream.append(event)
            self._total_packets += 1
            self._total_bytes += event.size

            if event.src:
                talker = self._top_talkers.get(event.src)
                if talker is None:
                    talker = {"pkts": 0, "bytes": 0, "last_seen": ts}
                    self._top_talkers[event.src] = talker
                talker["pkts"] += 1
                talker["bytes"] += event.size
                talker["last_seen"] = ts
                if len(self._top_talkers) > MAX_TALKERS:
                    self._evict_lru_talker()

            self._proto_counts[event.proto] = (
                self._proto_counts.get(event.proto, 0) + 1
            )

            self._update_velocity(ts, event.size)

    def update_many(self, events, now: float | None = None) -> None:
        """Record multiple events in one lock acquisition."""
        with self._lock:
            for event in events:
                self.update(event, now)

    def increment_dropped(self, count: int = 1) -> None:
        """Atomically increment the dropped-packet counter."""
        with self._lock:
            self._dropped += count

    def add_alert(self, alert: AlertEvent) -> None:
        """Append a detector alert to the rolling buffer and counter."""
        with self._lock:
            self._alerts.append(alert)
            self._alerts_total += 1

    def prune(self, now: float | None = None) -> int:
        """Purge talkers inactive for longer than ``TALKER_TTL`` seconds.

        Returns the number of entries removed.
        """
        ref = time.time() if now is None else now
        with self._lock:
            stale = [ip for ip, t in self._top_talkers.items()
                     if ref - t["last_seen"] > TALKER_TTL]
            for ip in stale:
                del self._top_talkers[ip]
            return len(stale)

    # ------------------------------------------------------------------
    # Snapshot API (UI thread) - deep copies, never shared references
    # ------------------------------------------------------------------

    def snapshot_stream(self) -> List[PacketEvent]:
        """Deep-copied list of the most recent ``STREAM_MAXLEN`` events."""
        with self._lock:
            return copy.deepcopy(list(self._stream))

    def snapshot_alerts(self) -> List[AlertEvent]:
        """Deep-copied list of the most recent ``ALERTS_MAXLEN`` alerts."""
        with self._lock:
            return copy.deepcopy(list(self._alerts))

    def snapshot_talkers(self) -> Dict[str, Dict]:
        """Deep-copied top-talker map: {ip: {"pkts", "bytes", "last_seen"}}."""
        with self._lock:
            return copy.deepcopy(self._top_talkers)

    def snapshot_telemetry(self) -> Dict:
        """Deep-copied telemetry summary (velocity, mix, counters)."""
        with self._lock:
            total = self._total_packets or 1
            mix = {proto: round(100.0 * count / total, 2)
                   for proto, count in self._proto_counts.items()}
            return {
                "packets_per_sec": round(self._pps, 3),
                "bytes_per_sec": round(self._bytes_sec, 3),
                "avg_packet_size": round(self._avg_size, 3),
                "protocol_mix": mix,
                "unique_hosts": len(self._top_talkers),
                "total_packets": self._total_packets,
                "total_bytes": self._total_bytes,
                "dropped_packets": self._dropped,
                "alerts_total": self._alerts_total,
            }

    # ------------------------------------------------------------------
    # Internal helpers (callers must hold the lock)
    # ------------------------------------------------------------------

    def _update_velocity(self, ts: float, size: int) -> None:
        if self._velocity_init:
            dt = ts - self._last_update
            if dt > 0:
                inst_pps = 1.0 / dt
                inst_bps = size / dt
                self._pps = EWMA_ALPHA * self._pps + EWMA_BETA * inst_pps
                self._bytes_sec = (
                    EWMA_ALPHA * self._bytes_sec + EWMA_BETA * inst_bps
                )
            self._avg_size = EWMA_ALPHA * self._avg_size + EWMA_BETA * size
        else:
            self._avg_size = float(size)
            self._velocity_init = True
        self._last_update = ts

    def _evict_lru_talker(self) -> None:
        oldest_ip = min(self._top_talkers, key=lambda ip: self._top_talkers[ip]["last_seen"])
        del self._top_talkers[oldest_ip]
