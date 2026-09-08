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
from typing import Deque, Dict, Iterable, List, Optional, Set, Tuple

from . import identity
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

# Minimum inter-packet delta (seconds) used for velocity estimates; clamps
# same-timestamp bursts so instantaneous rates stay finite instead of the
# EWMA freezing while the timestamp never advances.
MIN_DT_EPSILON = 1e-6

# Protocol buckets for the protocol-mix percentages.
PROTOCOLS = ("tcp", "udp", "icmp", "other")


class StateStore:
    """Thread-safe accumulation of all dashboard state."""

    def __init__(
        self,
        self_ips: Optional[Set[str]] = None,
        self_host: Optional[str] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._stream: Deque[PacketEvent] = deque(maxlen=STREAM_MAXLEN)
        self._alerts: Deque[AlertEvent] = deque(maxlen=ALERTS_MAXLEN)
        self._alerts_total = 0
        self._top_talkers: Dict[str, Dict] = {}
        self._proto_counts: Dict[str, int] = {p: 0 for p in PROTOCOLS}
        self._total_packets = 0
        self._total_bytes = 0
        self._dropped = 0

        # IP -> tags. Kept separate from ``_top_talkers`` so tags survive
        # LRU eviction and TTL pruning of a talker's telemetry.
        self._tags: Dict[str, Set[str]] = {}
        # Remote IP -> (local_port, remote_port, proto) of the last flow.
        # Used to resolve the local process for the scoped kill feature.
        self._flows: Dict[str, Tuple[int, int, str]] = {}

        # Automatic "this machine" tagging (self:<hostname>).
        self._self_ips = (
            frozenset(self_ips) if self_ips is not None else frozenset(identity.resolve_owned_ips())
        )
        self._self_host = self_host if self_host is not None else identity.hostname()

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

            if event.src in self._self_ips and event.dst:
                self._flows[event.dst] = (event.sport, event.dport, event.proto)
            if event.dst in self._self_ips and event.src:
                self._flows[event.src] = (event.dport, event.sport, event.proto)
            if event.src in self._self_ips:
                self._tag_self(event.src)
            if event.dst in self._self_ips:
                self._tag_self(event.dst)

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

    def add_tag(self, ip: str, tag: str) -> None:
        """Attach ``tag`` to ``ip`` (survives talker eviction/pruning)."""
        with self._lock:
            self._tags.setdefault(ip, set()).add(tag)

    def remove_tag(self, ip: str, tag: str) -> None:
        """Detach ``tag`` from ``ip``; drops the entry when the last tag goes."""
        with self._lock:
            tags = self._tags.get(ip)
            if tags is None:
                return
            tags.discard(tag)
            if not tags:
                del self._tags[ip]

    def load_tags(self, mapping: Dict[str, Iterable[str]]) -> None:
        """Bulk-import tags (used by ``--tags-file`` startup loading)."""
        with self._lock:
            for ip, tags in mapping.items():
                for tag in tags:
                    self._tags.setdefault(ip, set()).add(tag)

    def prune(self, now: float | None = None) -> int:
        """Purge talkers inactive for longer than ``TALKER_TTL`` seconds.

        Pinned talkers are never pruned so their mini-telemetry line stays
        visible. Returns the number of entries removed.
        """
        ref = time.time() if now is None else now
        with self._lock:
            stale = []
            for ip, talker in self._top_talkers.items():
                if (
                    ref - talker["last_seen"] > TALKER_TTL
                    and "pinned" not in self._tags.get(ip, ())
                ):
                    stale.append(ip)
            for ip in stale:
                del self._top_talkers[ip]
                self._flows.pop(ip, None)
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
        """Deep-copied top-talker map with tags merged in.

        Each entry: ``{"pkts", "bytes", "last_seen", "tags": [...]}``.
        """
        with self._lock:
            snap = copy.deepcopy(self._top_talkers)
            for ip, talker in snap.items():
                tags = self._tags.get(ip)
                talker["tags"] = sorted(tags) if tags else []
            return snap

    def snapshot_tags(self) -> Dict[str, List[str]]:
        """Deep-copied tag map: ``{ip: [tags]}`` (for ``--tags-file``)."""
        with self._lock:
            return {ip: sorted(tags) for ip, tags in self._tags.items()}

    def tags_for(self, ip: str) -> Set[str]:
        """Deep-copied set of tags currently attached to ``ip``."""
        with self._lock:
            return set(self._tags.get(ip, ()))

    def self_ips(self) -> Set[str]:
        """Snapshot of this host's own IPs (for stream direction markers)."""
        with self._lock:
            return set(self._self_ips)

    def snapshot_flow(self, ip: str) -> Optional[Dict]:
        """Last known flow for a remote ``ip``, or ``None``.

        Returns ``{"local_port", "remote_port", "proto"}`` where the local
        side is the host's own socket (used for scoped kill resolution).
        """
        with self._lock:
            flow = self._flows.get(ip)
            if flow is None:
                return None
            return {
                "local_port": flow[0],
                "remote_port": flow[1],
                "proto": flow[2],
            }

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

    def _tag_self(self, ip: str) -> None:
        """Attach the automatic ``self:<hostname>`` tag for an owned IP."""
        if ip in identity.LOOPBACK_IPS or ip.startswith("127."):
            tag = "self:localhost"
        else:
            tag = f"self:{self._self_host}"
        self._tags.setdefault(ip, set()).add(tag)

    def _update_velocity(self, ts: float, size: int) -> None:
        if self._velocity_init:
            dt = max(ts - self._last_update, MIN_DT_EPSILON)
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
