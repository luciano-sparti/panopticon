"""Defensive Scapy packet parser.

Converts a raw ``scapy.Packet`` into a normalized ``PacketEvent``.
All layer-attribute reads are guarded so corrupt, truncated, or non-IP
frames degrade to ``proto="other"`` with fallback values instead of
raising. Only ``AttributeError`` / ``IndexError`` are caught; unexpected
exceptions (including ``KeyboardInterrupt`` / ``SystemExit``) propagate.
"""

from __future__ import annotations

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

from .event import PacketEvent, service_for_port


def _fallback_event(pkt: Packet) -> PacketEvent:
    """Return a minimal "other" event for unparseable frames."""
    try:
        size = len(bytes(pkt))
    except Exception:  # noqa: BLE001 - catch any serialization/dissection error
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
        timestamp = float(getattr(pkt, "time", 0.0) or 0.0)
        size = len(bytes(pkt))
    except Exception:  # noqa: BLE001
        return _fallback_event(pkt)

    # Locate the network layer, skipping link layers (Ethernet, VLAN, etc.).
    try:
        ip = pkt.getlayer(IP)
        if ip is None:
            ip = pkt.getlayer(IPv6)
    except Exception:  # noqa: BLE001
        return _fallback_event(pkt)

    if ip is None:
        return _fallback_event(pkt)

    try:
        src = str(getattr(ip, "src", "") or "")
        dst = str(getattr(ip, "dst", "") or "")
    except Exception:  # noqa: BLE001
        return _fallback_event(pkt)

    proto = "other"
    sport = 0
    dport = 0
    flags = ""
    payload = b""

    try:
        tcp = pkt.getlayer(TCP)
        udp = pkt.getlayer(UDP)
        icmp = pkt.getlayer(ICMP)
    except Exception:  # noqa: BLE001
        tcp, udp, icmp = None, None, None

    if tcp is not None:
        proto = "tcp"
        try:
            sport = int(tcp.sport)
            dport = int(tcp.dport)
            flags = str(tcp.flags)
        except Exception:  # noqa: BLE001
            sport, dport, flags = 0, 0, ""
        try:
            payload = bytes(tcp.payload)
        except Exception:  # noqa: BLE001
            payload = b""
    elif udp is not None:
        proto = "udp"
        try:
            sport = int(udp.sport)
            dport = int(udp.dport)
        except Exception:  # noqa: BLE001
            sport, dport = 0, 0
        try:
            payload = bytes(udp.payload)
        except Exception:  # noqa: BLE001
            payload = b""
    elif icmp is not None:
        proto = "icmp"
        try:
            payload = bytes(icmp.payload)
        except Exception:  # noqa: BLE001
            payload = b""

    hostname, hostname_ip = _extract_hostname_info(proto, sport, dport, src, payload)

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
        payload=payload,
        hostname=hostname,
        hostname_ip=hostname_ip,
    )


def _fallback_packet() -> PacketEvent:
    """Zeroed fallback used when a ``None`` packet is passed in."""
    return PacketEvent(
        timestamp=0.0, src="", dst="", proto="other", sport=0, dport=0, size=0, service=""
    )


# ----------------------------------------------------------------------
# Hostname discovery (9.7): TLS SNI and DHCP hostname options are parsed
# straight off the transport payload so talkers get meaningful names
# without depending on reverse DNS.
# ----------------------------------------------------------------------

# Characters that may appear in a hostname (RFC 952/1123-ish, relaxed).
_HOSTNAME_OK = frozenset("abcdefghijklmnopqrstuvwxyz0123456789._-")
# TLS record content-type for a handshake message.
_TLS_HANDSHAKE = 0x16
# DHCP magic cookie (RFC 2132) that confirms a BOOTP payload carries options.
_DHCP_MAGIC = b"\x63\x82\x53\x63"
# DHCP option codes.
_OPT_HOST_NAME = 12
_OPT_END = 255


def _extract_hostname_info(
    proto: str, sport: int, dport: int, src: str, payload: bytes
) -> tuple[str, str]:
    """Return ``(hostname, owning_ip)`` learned from the payload, else ``("", "")``.

    ``owning_ip`` is the address the name describes (the TLS client for SNI,
    the lease holder for DHCP); it may differ from ``src`` (DHCP clients
    send from ``0.0.0.0`` before obtaining a lease).
    """
    try:
        if proto == "tcp" and payload and (sport == 443 or dport == 443):
            name = _tls_sni(payload)
            if name:
                return name, src
        elif proto == "udp" and payload and ({sport, dport} & {67, 68}):
            return _dhcp_hostname(payload, src)
    except Exception:  # noqa: BLE001 - name extraction must never raise
        return "", ""
    return "", ""


def _tls_sni(payload: bytes) -> str:
    """Extract the server_name from a TLS ClientHello, or ``""``.

    Walks up to four leading TLS records (a segmented handshake may span
    several); returns the first sane host name found. Pure byte math with
    explicit length checks, so it never raises on truncated input.
    """
    offset = 0
    for _ in range(4):
        if len(payload) - offset < 5 or payload[offset] != _TLS_HANDSHAKE:
            return ""
        rec_len = (payload[offset + 3] << 8) | payload[offset + 4]
        offset += 5
        if rec_len == 0:
            return ""
        handshake = payload[offset : offset + rec_len]
        if len(handshake) < 4 or handshake[0] != 1:  # 1 = ClientHello
            offset += rec_len
            continue
        name = _client_hello_sni(handshake[4:])
        if name:
            return name
        offset += rec_len
    return ""


def _client_hello_sni(body: bytes) -> str:
    """Parse a ClientHello body (after the 4-byte handshake header)."""
    if len(body) < 35:  # version(2) + random(32) + session_id_len(1)
        return ""
    pos = 35 + body[34]  # skip version, random, session_id
    if pos + 2 > len(body):
        return ""
    cipher_len = (body[pos] << 8) | body[pos + 1]
    pos += 2 + cipher_len
    if pos >= len(body):
        return ""
    pos += 1 + body[pos]  # compression methods
    if pos + 2 > len(body):
        return ""
    ext_len = (body[pos] << 8) | body[pos + 1]
    pos += 2
    end = min(pos + ext_len, len(body))
    while pos + 4 <= end:
        ext_type = (body[pos] << 8) | body[pos + 1]
        ext_data_len = (body[pos + 2] << 8) | body[pos + 3]
        pos += 4
        if ext_type == 0:  # server_name
            name = _sni_name_list(body[pos : pos + ext_data_len])
            if name:
                return name
        pos += ext_data_len
    return ""


def _sni_name_list(data: bytes) -> str:
    """Read the first host_name entry from an SNI extension body."""
    if len(data) < 5 or data[2] != 0:  # list_len(2) + type(1) == host_name
        return ""
    name_len = (data[3] << 8) | data[4]
    if name_len == 0 or 5 + name_len > len(data):
        return ""
    name = data[5 : 5 + name_len].decode("latin-1", "ignore")
    return name.lower() if _is_sane_hostname(name) else ""


def _dhcp_hostname(payload: bytes, src: str) -> tuple[str, str]:
    """Extract the DHCP host-name option, returning ``(name, owner_ip)``.

    ``owner_ip`` is the offered ``yiaddr`` when the client has not yet been
    leased an address (its ``src`` is ``0.0.0.0``), else ``src``.
    """
    if len(payload) < 240 or payload[236:240] != _DHCP_MAGIC:
        return "", ""
    pos = 240
    while pos < len(payload):
        tag = payload[pos]
        if tag == 0:  # padding
            pos += 1
            continue
        if tag == _OPT_END or pos + 1 >= len(payload):
            break
        opt_len = payload[pos + 1]
        pos += 2
        if tag == _OPT_HOST_NAME and opt_len and opt_len <= 64:
            name = payload[pos : pos + opt_len].decode("latin-1", "ignore")
            if _is_sane_hostname(name):
                lower = name.lower()
                if len(payload) >= 20:
                    owner = _ipv4_from_bytes(payload[16:20])
                    if owner and owner != "0.0.0.0":
                        return lower, owner
                return lower, src
        pos += opt_len
    return "", ""


def _ipv4_from_bytes(raw: bytes) -> str:
    if len(raw) != 4:
        return ""
    return ".".join(str(b) for b in raw)


def _is_sane_hostname(name: str) -> bool:
    """A hostname is sane when short, printable, and dot/underscore-safe."""
    if not name or len(name) > 253 or name[0] in ".-_":
        return False
    lowered = name.lower()
    return all(ch in _HOSTNAME_OK for ch in lowered)
