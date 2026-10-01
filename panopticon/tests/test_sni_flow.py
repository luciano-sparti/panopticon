"""Tests for TLS SNI extraction and flow domain mapping."""

import struct

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from panopticon.core.event import PacketEvent
from panopticon.core.parser import parse
from panopticon.core.store import StateStore


def _client_hello(server_name: str) -> bytes:
    """Build a minimal TLS ClientHello with the given SNI hostname."""
    name_bytes = server_name.encode("ascii")
    sni_entry = b"\x00" + struct.pack(">H", len(name_bytes)) + name_bytes
    sni_ext_data = struct.pack(">H", len(sni_entry)) + sni_entry
    ext_block = struct.pack(">H", 0) + struct.pack(">H", len(sni_ext_data)) + sni_ext_data
    ext_block = struct.pack(">H", len(ext_block)) + ext_block

    body = (
        b"\x03\x03"  # TLS 1.2
        + b"\x00" * 32  # random
        + b"\x00"  # session id len
        + b"\x00\x02\x13\x01"  # cipher suites
        + b"\x01\x00"  # compression methods
        + ext_block
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def test_tls_sni_populates_event_sni():
    payload = _client_hello("api.github.com")
    ip_layer = IP(src="10.0.0.5", dst="140.82.121.4")
    raw_pkt = Ether() / ip_layer / TCP(sport=50000, dport=443) / Raw(payload)
    event = parse(raw_pkt)
    assert event.sni == "api.github.com"


def test_tls_sni_maps_to_destination_in_store():
    store = StateStore()
    event = PacketEvent(
        timestamp=1.0,
        src="10.0.0.5",
        dst="140.82.121.4",
        proto="tcp",
        sport=50000,
        dport=443,
        size=350,
        service="https",
        sni="api.github.com",
    )
    store.update(event)
    # The destination IP 140.82.121.4 should be mapped to the SNI domain name
    assert store._hostnames.get("140.82.121.4") == "api.github.com"
