"""Defensive Scapy packet parser.

Converts a raw ``scapy.Packet`` into a normalized ``PacketEvent``.
All layer-attribute reads are guarded so corrupt, truncated, or non-IP
frames degrade to ``proto="other"`` with fallback values instead of
raising. Only ``AttributeError`` / ``IndexError`` are caught; unexpected
exceptions (including ``KeyboardInterrupt`` / ``SystemExit``) propagate.
"""

from __future__ import annotations

from typing import Optional

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

from .event import PacketEvent, service_for_port


def _fallback_event(pkt: Packet) -> PacketEvent:
    """Return a minimal "other" event for unparseable frames."""
    try:
        size = len(bytes(pkt))
    except (AttributeError, IndexError):
        size = 0
    return PacketEvent(
        timestamp=float(getattr(pkt, "time", 0.0) or 0.0),
        src="",
        dst="",
        proto="other",
        sport=0,
        dport=0,
        size=size,
        service="",
    )


def parse(pkt: Packet) -> PacketEvent:
    """Parse a Scapy packet into a ``PacketEvent``.

    Layer inspection order: Ethernet -> IP (IPv4/IPv6) -> TCP/UDP/ICMP.
    Non-IP and malformed packets produce ``proto="other"`` with defaults.
    """
    if pkt is None:
        return _fallback_packet()

    try:
        timestamp = float(pkt.time or 0.0)
        size = len(bytes(pkt))
    except (AttributeError, IndexError):
        return _fallback_event(pkt)

    # Locate the network layer, skipping link layers (Ethernet, VLAN, etc.).
    ip = pkt.getlayer(IP)
    if ip is None:
        ip = pkt.getlayer(IPv6)
    if ip is None:
        return _fallback_event(pkt)

    try:
        src = ip.src
        dst = ip.dst
    except (AttributeError, IndexError):
        return _fallback_event(pkt)

    proto = "other"
    sport = 0
    dport = 0
    flags = ""

    tcp = pkt.getlayer(TCP)
    udp = pkt.getlayer(UDP)
    icmp = pkt.getlayer(ICMP)

    if tcp is not None:
        proto = "tcp"
        try:
            sport = int(tcp.sport)
            dport = int(tcp.dport)
            flags = str(tcp.flags)
        except (AttributeError, IndexError):
            sport, dport, flags = 0, 0, ""
    elif udp is not None:
        proto = "udp"
        try:
            sport = int(udp.sport)
            dport = int(udp.dport)
        except (AttributeError, IndexError):
            sport, dport = 0, 0
    elif icmp is not None:
        proto = "icmp"

    service = service_for_port(dport) if dport else ""
    return PacketEvent(
        timestamp=timestamp,
        src=src,
        dst=dst,
        proto=proto,
        sport=sport,
        dport=dport,
        size=size,
        service=service,
        flags=flags,
    )


def _fallback_packet() -> PacketEvent:
    """Zeroed fallback used when a ``None`` packet is passed in."""
    return PacketEvent(
        timestamp=0.0, src="", dst="", proto="other", sport=0, dport=0, size=0, service=""
    )
