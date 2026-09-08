"""Shared data structures for Panopticon.

Defines the normalized packet event, the alert event, and the static
service-name lookup used by the parser and the UI.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PacketEvent:
    """A normalized, immutable view of a single captured packet.

    Attributes:
        timestamp: Unix epoch seconds when the packet was captured
            (from ``pkt.time``).
        src: Source IP address string, or empty string when unavailable.
        dst: Destination IP address string, or empty string when unavailable.
        proto: Transport protocol, one of "tcp", "udp", "icmp", "other".
        sport: Source port, 0 when not applicable (e.g. ICMP).
        dport: Destination port, 0 when not applicable (e.g. ICMP).
        size: Total captured packet size in bytes (link-layer frame length).
        service: Well-known service name for ``dport`` (e.g. "http"), or
            empty string when unknown.
        flags: TCP control flags string (e.g. "S", "SA", "R"), or empty
            string for non-TCP traffic.
        payload: Transport-layer payload bytes (everything after the L4
            header), or empty bytes when unavailable. Extracted once at
            parse time so detectors do not re-dissect the raw frame.
    """

    timestamp: float
    src: str
    dst: str
    proto: str
    sport: int
    dport: int
    size: int
    service: str
    flags: str = ""
    payload: bytes = b""


@dataclass(frozen=True)
class AlertEvent:
    """An anomaly / threat finding produced by a detector.

    Attributes:
        time: Unix epoch seconds when the alert was raised.
        severity: Severity level, e.g. "info", "warn", "critical".
        kind: Alert kind, e.g. "syn_scan", "plaintext", "high_port".
        summary: Human-readable description of the alert.
        src: Source IP associated with the alert.
        dst: Destination IP associated with the alert.
    """

    time: float
    severity: str
    kind: str
    summary: str
    src: str
    dst: str


# Static service-name map for well-known destination ports.
SERVICE_MAP = {
    80: "http",
    443: "https",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    123: "ntp",
    3306: "mysql",
    5432: "postgres",
}

# Ports at or above this value are ephemeral / registered as "high".
EPHEMERAL_PORT = 49152


def service_for_port(port: int) -> str:
    """Return a service name for a destination port, else empty string.

    Ports >= ``EPHEMERAL_PORT`` map to the "ephemeral" pseudo-service.
    """
    if port >= EPHEMERAL_PORT:
        return "ephemeral"
    return SERVICE_MAP.get(port, "")
