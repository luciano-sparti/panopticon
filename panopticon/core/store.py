"""Thread-safe central state store for Panopticon.

All shared state (rolling stream buffer, top talkers, EWMA velocity
metrics, protocol mix, per-cause drop counters) lives here behind a single
``threading.RLock``. Snapshot methods return short-lived copies:
frozen-dataclass events (with immutable ``payload`` bytes) are handed out as
list copies, mutable talker records are shallow-copied per row, so the UI
thread never mutates store-owned state and never pays for deep copies.
"""

from __future__ import annotations

import heapq
import threading
from collections import deque
from collections.abc import Iterable

from . import identity
from .clock import Clock
from .event import AlertEvent, PacketEvent
from .lru import evict_lru
from .names import HostnameResolver, classify_ip

# Rolling stream buffer length (kept on-screen / in UI).
STREAM_MAXLEN = 500
# Rolling alert buffer length (kept on-screen / in UI).
ALERTS_MAXLEN = 200
# Maximum tracked talker IPs; beyond this the least-recently-seen is evicted.
MAX_TALKERS = 5000
# Inactive talkers are purged when idle for longer than this (seconds).
TALKER_TTL = 300
# Sessions (conversations) idle for longer than this are purged on prune.
SESSION_TTL = 300
# Maximum tracked concurrent sessions (LRU-evicted beyond this).
MAX_SESSIONS = 5000
# EWMA weights: new_value = EWMA_ALPHA * old + EWMA_BETA * observed.
EWMA_ALPHA = 0.9
EWMA_BETA = 0.1

# Minimum inter-flush delta (seconds) used for velocity estimates; clamps
# same-tick flushes so instantaneous rates stay finite instead of the EWMA
# freezing while the timestamp never advances.
MIN_DT_EPSILON = 1e-6

# Protocol buckets for the protocol-mix percentages.
PROTOCOLS = ("tcp", "udp", "icmp", "other")


class StateStore:
    """Thread-safe accumulation of all dashboard state."""

    def __init__(
        self,
        self_ips: set[str] | None = None,
        self_host: str | None = None,
        clock: Clock | None = None,
        names: HostnameResolver | None = None,
    ) -> None:
        self._clock = clock if clock is not None else Clock()
        self._names = names
        self._lock = threading.RLock()
        self._stream: deque[PacketEvent] = deque(maxlen=STREAM_MAXLEN)
        self._alerts: deque[AlertEvent] = deque(maxlen=ALERTS_MAXLEN)
        self._alerts_total = 0
        self._top_talkers: dict[str, dict] = {}
        self._proto_counts: dict[str, int] = {p: 0 for p in PROTOCOLS}
        self._total_packets = 0
        self._total_bytes = 0
        # Per-cause drop accounting, split by sniffer.handle_packet: frames
        # that failed parsing vs. frames rejected by a full capture queue.
        self._parse_failures = 0
        self._queue_drops = 0

        # IP -> tags. Kept separate from ``_top_talkers`` so tags survive
        # LRU eviction and TTL pruning of a talker's telemetry.
        self._tags: dict[str, set[str]] = {}
        # IP -> classify_ip() result, memoized so twice-a-second snapshots of
        # up to ``MAX_TALKERS`` entries never re-parse the same addresses.
        self._class_cache: dict[str, str] = {}
        # IP -> hostname learned from the wire (TLS SNI / DHCP option 12).
        # Higher confidence than reverse DNS, so it wins over PTR names.
        self._hostnames: dict[str, str] = {}
        # Canonical session key (src, sport, dst, dport, proto) -> record.
        # Tracked so the UI can show live conversations and the scan
        # detectors can correlate replies; bounded by ``MAX_SESSIONS``.
        self._sessions: dict[tuple[str, int, str, int, str], dict] = {}
        # Remote IP -> (local_port, remote_port, proto) of the last flow.
        # Used to resolve the local process for the scoped kill feature.
        self._flows: dict[str, tuple[int, int, str]] = {}

        # Automatic "this machine" tagging (self:<hostname>).
        self._self_ips = (
            frozenset(self_ips) if self_ips is not None else frozenset(identity.resolve_owned_ips())
        )
        self._self_host = self_host if self_host is not None else identity.hostname()

        # EWMA velocity state, folded once per refresh tick (flush_velocity).
        self._pps = 0.0
        self._bytes_sec = 0.0
        self._avg_size = 0.0
        self._velocity_init = False
        self._last_flush: float = self._clock.now()
        # Per-tick accumulation, drained by flush_velocity.
        self._acc_pkts = 0
        self._acc_bytes = 0
        self._acc_size_sum = 0

    # ------------------------------------------------------------------
    # Mutation API (called by the pipeline worker thread)
    # ------------------------------------------------------------------

    def update(self, event: PacketEvent, now: float | None = None) -> None:
        """Record a single packet event (stream, talkers, velocity, mix)."""
        ts = event.timestamp if now is None else now
        with self._lock:
            if not self._velocity_init and self._last_flush > ts:
                self._last_flush = ts
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

            self._proto_counts[event.proto] = self._proto_counts.get(event.proto, 0) + 1

            if event.src in self._self_ips and event.dst:
                self._flows[event.dst] = (event.sport, event.dport, event.proto)
            if event.dst in self._self_ips and event.src:
                self._flows[event.src] = (event.dport, event.sport, event.proto)
            if event.src in self._self_ips:
                self._tag_self(event.src)
            if event.dst in self._self_ips:
                self._tag_self(event.dst)

            if event.hostname:
                owner = event.hostname_ip or event.src
                if owner:
                    self._hostnames[owner] = event.hostname
                    # A DHCP lease names a host that may not have sent a
                    # packet yet (its src is 0.0.0.0); surface it as a
                    # talker so the name is immediately visible.
                    if owner != event.src and owner not in self._top_talkers:
                        self._top_talkers[owner] = {
                            "pkts": 0,
                            "bytes": 0,
                            "last_seen": ts,
                        }
                        if len(self._top_talkers) > MAX_TALKERS:
                            self._evict_lru_talker()

            self._track_session(event, ts)

            self._acc_pkts += 1
            self._acc_bytes += event.size
            self._acc_size_sum += event.size

    def increment_parse_failure(self, count: int = 1) -> None:
        """Atomically count a frame that failed parsing."""
        with self._lock:
            self._parse_failures += count

    def increment_queue_drop(self, count: int = 1) -> None:
        """Atomically count a frame dropped for a full capture queue."""
        with self._lock:
            self._queue_drops += count

    def flush_velocity(self, now: float | None = None) -> None:
        """Fold per-tick accumulated counters into the EWMA velocity state.

        Called once per refresh tick (see ``analyzer.main``) instead of on
        every packet, so instantaneous rates reflect whole ticks rather than
        the gap between two consecutive packets. Idle ticks (no packets) only
        advance the baseline timestamp; an idle gap must not drag the rate
        toward zero while nothing arrives. ``avg_packet_size`` is the one
        value seeded exactly: it measures sample means, so the EWMA warm-up
        must not halve its first sample.
        """
        ts = self._clock.now() if now is None else now
        with self._lock:
            if not self._velocity_init and self._last_flush > ts:
                self._last_flush = ts
            dt = max(ts - self._last_flush, MIN_DT_EPSILON)
            if self._acc_pkts:
                self._pps = EWMA_ALPHA * self._pps + EWMA_BETA * (self._acc_pkts / dt)
                self._bytes_sec = EWMA_ALPHA * self._bytes_sec + EWMA_BETA * (self._acc_bytes / dt)
                avg = self._acc_size_sum / self._acc_pkts
                if self._velocity_init:
                    self._avg_size = EWMA_ALPHA * self._avg_size + EWMA_BETA * avg
                else:
                    self._avg_size = avg
                    self._velocity_init = True
            self._last_flush = ts
            self._acc_pkts = 0
            self._acc_bytes = 0
            self._acc_size_sum = 0

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

    def load_tags(self, mapping: dict[str, Iterable[str]]) -> None:
        """Bulk-import tags (used by ``--tags-file`` startup loading)."""
        with self._lock:
            for ip, tags in mapping.items():
                for tag in tags:
                    self._tags.setdefault(ip, set()).add(tag)

    def prune(self, now: float | None = None) -> int:
        """Purge stale talkers and closed/idle sessions.

        Sessions idle for longer than ``SESSION_TTL`` are dropped in the
        same pass. Returns the number of talker records removed (the return
        semantics predate session tracking and tests rely on it).
        """
        ref = self._clock.now() if now is None else now
        with self._lock:
            stale = []
            for ip, talker in self._top_talkers.items():
                if ref - talker["last_seen"] > TALKER_TTL and "pinned" not in self._tags.get(
                    ip, ()
                ):
                    stale.append(ip)
            for ip in stale:
                del self._top_talkers[ip]
                self._class_cache.pop(ip, None)
                self._hostnames.pop(ip, None)
                self._flows.pop(ip, None)
            self._prune_sessions(ref)
            return len(stale)

    def pump_hostnames(self, limit: int = 64) -> None:
        """Kick background reverse-DNS lookups for the busiest talkers.

        No-op when no resolver is attached. Cheap and non-blocking; the
        resolver caches answers and dedupes in-flight lookups.
        """
        if self._names is None:
            return
        with self._lock:
            ips = sorted(
                self._top_talkers,
                key=lambda ip: self._top_talkers[ip].get("bytes", 0),
                reverse=True,
            )[: max(limit, 1)]
        self._names.kick(ips)

    # ------------------------------------------------------------------
    # Snapshot API (UI thread) - short-lived copies, never shared mutables
    # ------------------------------------------------------------------

    def snapshot_stream(self) -> list[PacketEvent]:
        """Copy of the rolling stream buffer.

        Events are frozen dataclasses (including the immutable ``payload``
        bytes), so a list copy is a safe, reference-sharing snapshot.
        """
        with self._lock:
            return list(self._stream)

    def snapshot_alerts(self) -> list[AlertEvent]:
        """Copy of the rolling alert buffer (frozen dataclasses)."""
        with self._lock:
            return list(self._alerts)

    def snapshot_talkers(self) -> dict[str, dict]:
        """Copy of the top-talker map with tags merged in.

        Each entry: ``{"pkts", "bytes", "last_seen", "tags": [...],
        "class": <category>, "name": <resolved hostname or "">}``.

        Inner talker records are small mutable dicts owned by the worker;
        each is shallow-copied here (scalar values only) so the UI gets its
        own record to mutate with no deep-copy cost.
        """
        with self._lock:
            snap = {ip: dict(talker) for ip, talker in self._top_talkers.items()}
            for ip, talker in snap.items():
                tags = self._tags.get(ip)
                talker["tags"] = sorted(tags) if tags else []
                cls = self._class_cache.get(ip)
                if cls is None:
                    cls = classify_ip(ip)
                    self._class_cache[ip] = cls
                talker["class"] = cls
                name = self._hostnames.get(ip)
                if not name and self._names is not None:
                    name = self._names.name_for(ip)
                talker["name"] = name or ""
            return snap

    def snapshot_tags(self) -> dict[str, list[str]]:
        """Copy of the tag map: ``{ip: [tags]}`` (for ``--tags-file``)."""
        with self._lock:
            return {ip: sorted(tags) for ip, tags in self._tags.items()}

    def tags_for(self, ip: str) -> set[str]:
        """Copy of the set of tags currently attached to ``ip``."""
        with self._lock:
            return set(self._tags.get(ip, ()))

    def self_ips(self) -> set[str]:
        """Snapshot of this host's own IPs (for stream direction markers)."""
        with self._lock:
            return set(self._self_ips)

    def snapshot_sessions(self, ip: str | None = None, limit: int = 50) -> list[dict]:
        """Most recently seen sessions, newest first.

        ``ip`` optionally filters to sessions touching that address. Each
        record: ``{"src", "sport", "dst", "dport", "proto", "state", "pkts",
        "bytes", "first_seen", "last_seen"}``.
        """
        with self._lock:
            rows = []
            for key, rec in self._sessions.items():
                f_src, f_sport, f_dst, f_dport, f_proto = key
                if ip and f_src != ip and f_dst != ip:
                    continue
                row = dict(rec)
                row.update(
                    {
                        "src": f_src,
                        "sport": f_sport,
                        "dst": f_dst,
                        "dport": f_dport,
                        "proto": f_proto,
                    }
                )
                rows.append(row)
            if limit and len(rows) > limit:
                return heapq.nlargest(limit, rows, key=lambda r: r["last_seen"])
            rows.sort(key=lambda r: r["last_seen"], reverse=True)
            return rows[:limit]

    def snapshot_flow(self, ip: str) -> dict | None:
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

    def snapshot_telemetry(self) -> dict:
        """Fresh telemetry summary (velocity, mix, counters)."""
        with self._lock:
            total = self._total_packets or 1
            mix = {
                proto: round(100.0 * count / total, 2)
                for proto, count in self._proto_counts.items()
            }
            return {
                "packets_per_sec": round(self._pps, 3),
                "bytes_per_sec": round(self._bytes_sec, 3),
                "avg_packet_size": round(self._avg_size, 3),
                "protocol_mix": mix,
                "unique_hosts": len(self._top_talkers),
                "active_sessions": sum(
                    1 for rec in self._sessions.values() if rec["state"] != "closed"
                ),
                "total_packets": self._total_packets,
                "total_bytes": self._total_bytes,
                "dropped_packets": self._parse_failures + self._queue_drops,
                "parse_failures": self._parse_failures,
                "queue_drops": self._queue_drops,
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

    def _evict_lru_talker(self) -> None:
        def _cleanup(ip: str) -> None:
            self._class_cache.pop(ip, None)
            self._hostnames.pop(ip, None)

        evict_lru(
            self._top_talkers,
            last_seen=lambda ip: self._top_talkers[ip]["last_seen"],
            cap=MAX_TALKERS,
            on_evict=_cleanup,
        )

    # ------------------------------------------------------------------
    # Session tracking (9.8)
    # ------------------------------------------------------------------

    def _track_session(self, event: PacketEvent, now: float) -> None:
        if not event.src or not event.dst:
            return
        key = (event.src, event.sport, event.dst, event.dport, event.proto)
        rec = self._sessions.get(key)
        if rec is None:
            self._sessions[key] = {
                "pkts": 1,
                "bytes": event.size,
                "first_seen": now,
                "last_seen": now,
                "state": _session_state(event.proto, event.flags or "", ""),
            }
        else:
            rec["pkts"] += 1
            rec["bytes"] += event.size
            rec["last_seen"] = now
            rec["state"] = _session_state(event.proto, event.flags or "", rec["state"])
        if len(self._sessions) > MAX_SESSIONS:
            self._evict_lru_session()

    def _prune_sessions(self, now: float) -> int:
        """Drop sessions idle for longer than ``SESSION_TTL``."""
        stale = [key for key, rec in self._sessions.items() if now - rec["last_seen"] > SESSION_TTL]
        for key in stale:
            del self._sessions[key]
        return len(stale)

    def _evict_lru_session(self) -> None:
        evict_lru(
            self._sessions,
            last_seen=lambda key: self._sessions[key]["last_seen"],
            cap=MAX_SESSIONS,
        )


def _session_state(proto: str, flags: str, prev: str) -> str:
    """Derive a session state from a TCP/UDP event's flags.

    ``handshake`` (SYN, no ACK) -> ``established`` (SYN-ACK or ACK) ->
    ``closed`` (FIN/RST). Non-TCP conversations are ``active``.
    """
    if proto != "tcp":
        return "active"
    if "R" in flags or "F" in flags:
        return "closed"
    if "S" in flags or "A" in flags:
        return "established" if "A" in flags else "handshake"
    return prev or "established"
