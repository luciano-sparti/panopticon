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

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Packet

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
    engine_cooldown: float | None = None

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
        raw: bytes | None = None,
    ) -> AlertEvent | None:
        port_hit = event.dport in PLAINTEXT_PORTS or event.sport in PLAINTEXT_PORTS
        marker = self._find_marker(raw, event.proto)

        if port_hit and (not self._payload_gate or marker is not None):
            if event.dport in PLAINTEXT_PORTS:
                port = event.dport
                direction = "to"
            else:
                port = event.sport
                direction = "from"
            service = PLAINTEXT_PORTS[port]
            return AlertEvent(
                time=now,
                severity="warn",
                kind="plaintext",
                summary=(
                    f"unencrypted {service} traffic {direction} port {port}"
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
                summary=(f"cleartext marker {marker.decode('ascii', 'replace')!r} in payload"),
                src=event.src,
                dst=event.dst,
            )

        return None

    def _find_marker(self, raw: bytes | None, proto: str) -> bytes | None:
        """Return the first cleartext marker found in the payload head.

        Transport-layer headers are stripped before scanning so scan budget
        is spent on real payload bytes rather than on binary L2/L3/L4 headers
        (which can coincidentally contain ``USER `` / ``PASS `` sequences).
        Frames that cannot be dissected fall back to scanning the raw head.
        """
        if not raw:
            return None
        payload = _payload_bytes(raw) if proto in ("tcp", "udp", "icmp") else None
        if payload is None:
            payload = raw
        head = payload[: self._max_scan]
        for marker in PLAINTEXT_MARKERS:
            if marker in head:
                return marker
        return None


def _payload_bytes(raw: bytes) -> bytes | None:
    """Return the L4 payload bytes of ``raw``, or ``None`` when no L4 layer.

    ``None`` (rather than empty bytes) lets callers distinguish "dissection
    reached a transport layer with no payload" from "the frame could not be
    dissected at all".
    """
    pkt = _dissect(raw)
    if pkt is None:
        return None
    for layer_cls in (TCP, UDP, ICMP):
        layer = pkt.getlayer(layer_cls)
        if layer is not None:
            return bytes(layer.payload)
    return None


def _dissect(raw: bytes) -> Packet | None:
    """Best-effort dissection of a raw frame down to a transport layer."""
    if not raw:
        return None
    for cls in (Ether, IP, IPv6):
        try:
            pkt = cls(raw)
        except Exception:  # noqa: BLE001, S112 - corrupt/truncated frames
            continue
        if (
            pkt.getlayer(TCP) is not None
            or pkt.getlayer(UDP) is not None
            or pkt.getlayer(ICMP) is not None
        ):
            return pkt
    return None
