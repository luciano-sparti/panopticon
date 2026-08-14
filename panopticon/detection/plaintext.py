"""Plaintext / cleartext-traffic detection.

Two tiers:

(a) Port-based: the destination or source port is a well-known plaintext
    service (http/80, ftp/21, telnet/23, smtp/25). Optionally gated on
    payload evidence via ``payload_gate``.

(b) Payload-based: the first ``max_scan_bytes`` of the raw frame are scanned
    for cleartext markers. Credential-bearing lines (Authorization, USER,
    PASS) raise ``warn``; plaintext HTTP verbs (GET, POST) raise ``info``.

Engine-level dedup keyed by ``(kind, src)`` keeps per-source volume bounded.
"""

from __future__ import annotations

from typing import Optional

from ..core.event import AlertEvent, PacketEvent
from .base import BaseDetector

# Well-known plaintext services by port.
PLAINTEXT_PORTS = {80: "http", 21: "ftp", 23: "telnet", 25: "smtp"}

# Cleartext markers, in priority order; credential-ish markers rate ``warn``.
PLAINTEXT_MARKERS = (b"Authorization: ", b"USER ", b"PASS ", b"GET /", b"POST ")
WARN_MARKERS = (b"Authorization: ", b"USER ", b"PASS ")

# Bytes of payload scanned per frame for marker detection.
DEFAULT_PAYLOAD_SCAN_BYTES = 256


class PlaintextDetector(BaseDetector):
    """Flags unencrypted services and cleartext credential material."""

    # Engine dedup keyed by (kind, src).
    engine_cooldown: Optional[float] = None

    def __init__(
        self,
        payload_gate: bool = False,
        max_scan_bytes: int = DEFAULT_PAYLOAD_SCAN_BYTES,
    ) -> None:
        self._payload_gate = payload_gate
        self._max_scan = max_scan_bytes

    def process_event(
        self,
        event: PacketEvent,
        now: float,
        raw: Optional[bytes] = None,
    ) -> Optional[AlertEvent]:
        port_hit = (
            event.dport in PLAINTEXT_PORTS or event.sport in PLAINTEXT_PORTS
        )
        marker = self._find_marker(raw)

        if port_hit and (not self._payload_gate or marker is not None):
            service = (
                PLAINTEXT_PORTS.get(event.dport)
                or PLAINTEXT_PORTS.get(event.sport)
                or "plaintext"
            )
            port = event.dport or event.sport
            return AlertEvent(
                time=now,
                severity="warn",
                kind="plaintext",
                summary=(
                    f"unencrypted {service} traffic on port {port}"
                    + (f" ({marker.decode('ascii', 'replace')!r})" if marker else "")
                ),
                src=event.src,
                dst=event.dst,
            )

        if marker is not None:
            severity = "warn" if marker in WARN_MARKERS else "info"
            return AlertEvent(
                time=now,
                severity=severity,
                kind="plaintext",
                summary=(
                    f"cleartext marker {marker.decode('ascii', 'replace')!r} "
                    "in payload"
                ),
                src=event.src,
                dst=event.dst,
            )

        return None

    def _find_marker(self, raw: Optional[bytes]) -> Optional[bytes]:
        """Return the first cleartext marker found in the payload head."""
        if not raw:
            return None
        head = raw[: self._max_scan]
        for marker in PLAINTEXT_MARKERS:
            if marker in head:
                return marker
        return None
