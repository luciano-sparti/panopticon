"""Tests for the defensive packet parser (no root / live capture needed)."""

import struct

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw

from panopticon.core.parser import parse


def make(pkt: Packet, time: float = 1234.5) -> Packet:
    pkt.time = time
    return pkt


def test_tcp_http_parsing():
    pkt = make(
        Ether()
        / IP(src="10.0.0.1", dst="8.8.8.8")
        / TCP(sport=40000, dport=80, flags="S")
        / Raw(b"GET /"),
    )
    ev = parse(pkt)
    assert ev.src == "10.0.0.1"
    assert ev.dst == "8.8.8.8"
    assert ev.proto == "tcp"
    assert ev.sport == 40000
    assert ev.dport == 80
    assert ev.service == "http"
    assert ev.timestamp == 1234.5
    assert ev.size == len(bytes(pkt))
    assert ev.payload == b"GET /"


def test_tcp_ephemeral_dport_maps_to_ephemeral_service():
    pkt = make(
        Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1111, dport=55000, flags="S"),
    )
    ev = parse(pkt)
    assert ev.dport == 55000
    assert ev.service == "ephemeral"


def test_tcp_known_port_maps_to_service():
    pkt = make(
        Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=50000, dport=5432),
    )
    assert parse(pkt).service == "postgres"


def test_udp_dns_parsing():
    pkt = make(
        Ether() / IP(src="192.168.1.5", dst="9.9.9.9") / UDP(sport=54321, dport=53),
    )
    ev = parse(pkt)
    assert ev.proto == "udp"
    assert ev.sport == 54321
    assert ev.dport == 53
    assert ev.service == "dns"


def test_icmp_parsing_has_zero_ports():
    pkt = make(
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=8, code=0),
    )
    ev = parse(pkt)
    assert ev.proto == "icmp"
    assert ev.sport == 0
    assert ev.dport == 0
    assert ev.service == ""


def test_payload_extracted_once_per_transport_proto():
    tcp = parse(make(Ether() / IP() / TCP(sport=1, dport=80) / Raw(b"tcp-payload")))
    udp = parse(make(Ether() / IP() / UDP(sport=1, dport=53) / Raw(b"udp-payload")))
    icmp = parse(make(Ether() / IP() / ICMP(type=8, code=0) / Raw(b"") / Raw(b"icmp-payload")))
    assert tcp.payload == b"tcp-payload"
    assert udp.payload == b"udp-payload"
    assert icmp.payload == b"icmp-payload"
    # No payload -> empty bytes, not None.
    empty = parse(make(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1, dport=80)))
    assert empty.payload == b""


def test_ipv6_tcp_parsing():
    pkt = make(
        IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=2222, dport=22),
    )
    ev = parse(pkt)
    assert ev.src == "2001:db8::1"
    assert ev.dst == "2001:db8::2"
    assert ev.proto == "tcp"
    assert ev.dport == 22
    assert ev.service == "ssh"


def test_non_ip_packet_falls_back_to_other():
    raw = make(Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff") / Raw(b"junk"))
    ev = parse(raw)
    assert ev.proto == "other"
    assert ev.src == ""
    assert ev.dst == ""
    assert ev.sport == 0
    assert ev.dport == 0
    assert ev.service == ""


def test_no_transport_layer_yields_other_proto_with_ips():
    # IP-only frame: IP fields are available, but no TCP/UDP/ICMP layer.
    pkt = make(IP(src="10.0.0.1", dst="10.0.0.2"))
    ev = parse(pkt)
    assert ev.proto == "other"
    assert ev.src == "10.0.0.1"
    assert ev.dst == "10.0.0.2"
    assert ev.sport == 0
    assert ev.dport == 0
    assert ev.size == len(bytes(pkt))


def test_none_packet_returns_zeroed_event():
    ev = parse(None)
    assert ev.proto == "other"
    assert ev.timestamp == 0.0
    assert ev.size == 0


def test_tcp_flags_are_parsed():
    pkt = make(
        Ether() / IP(src="10.0.0.1", dst="8.8.8.8") / TCP(sport=40000, dport=80, flags="S"),
    )
    assert parse(pkt).flags == "S"


def test_tcp_syn_ack_flags_are_parsed():
    pkt = make(
        Ether() / IP(src="8.8.8.8", dst="10.0.0.1") / TCP(sport=80, dport=40000, flags="SA"),
    )
    assert parse(pkt).flags == "SA"


def test_non_tcp_flags_are_empty():
    pkt = make(
        Ether() / IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=50000, dport=53),
    )
    assert parse(pkt).flags == ""


def test_corrupt_packet_bytes_raises_exception():
    class CorruptPacket:
        time = 100.0

        def __bytes__(self):
            raise ValueError("Corrupted wire data")

        def getlayer(self, cls):
            raise TypeError("Corrupted layer")

    ev = parse(CorruptPacket())
    assert ev.proto == "other"
    assert ev.size == 0
    assert ev.timestamp == 100.0


def test_corrupt_transport_layer_recovers_gracefully():
    class BrokenTcpPacket:
        time = 200.0

        def __bytes__(self):
            return bytes(40)

        def getlayer(self, cls):
            if cls == IP:
                return IP(src="1.1.1.1", dst="2.2.2.2")
            if cls == TCP:

                class BrokenTCP:
                    @property
                    def sport(self):
                        raise RuntimeError("Broken field")

                return BrokenTCP()
            return None

    ev = parse(BrokenTcpPacket())
    assert ev.src == "1.1.1.1"
    assert ev.dst == "2.2.2.2"
    assert ev.proto == "tcp"
    assert ev.sport == 0
    assert ev.dport == 0


# ----------------------------------------------------------------------
# 9.7 hostname discovery: TLS SNI and DHCP host-name option
# ----------------------------------------------------------------------


def _client_hello(name: str) -> bytes:
    """Handcraft a minimal TLS 1.2 ClientHello carrying an SNI extension."""
    entry = b"\x00" + struct.pack(">H", len(name)) + name.encode()
    list_data = struct.pack(">H", len(entry)) + entry
    sni_ext = b"\x00\x00" + struct.pack(">H", len(list_data)) + list_data
    ext_block = struct.pack(">H", len(sni_ext)) + sni_ext
    body = (
        b"\x03\x03"  # TLS 1.2
        + bytes(32)  # random
        + b"\x00"  # session id len
        + struct.pack(">H", 2)
        + b"\x13\x01"
        + b"\x01\x00"  # compression methods
        + ext_block
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def test_tls_sni_extracts_hostname():
    payload = _client_hello("Chat.Example.COM")
    pkt = make(
        Ether() / IP(src="10.0.0.9", dst="1.2.3.4") / TCP(sport=55000, dport=443) / Raw(payload),
    )
    ev = parse(pkt)
    assert ev.hostname == "chat.example.com"
    assert ev.hostname_ip == "10.0.0.9"


def test_tls_sni_ignored_on_non_443():
    payload = _client_hello("chat.example.com")
    pkt = make(
        Ether() / IP(src="10.0.0.9", dst="1.2.3.4") / TCP(sport=55000, dport=8443) / Raw(payload),
    )
    ev = parse(pkt)
    assert ev.hostname == ""


def test_tls_non_clienthello_record_yields_no_hostname():
    # A TLS record that is not a handshake (0x17 = application data).
    junk = b"\x17\x03\x01" + struct.pack(">H", 4) + b"\x00\x01\x02\x03"
    pkt = make(
        Ether() / IP(src="10.0.0.9", dst="1.2.3.4") / TCP(sport=55000, dport=443) / Raw(junk),
    )
    assert parse(pkt).hostname == ""


def test_tls_truncated_payload_yields_no_hostname():
    pkt = make(
        Ether()
        / IP(src="10.0.0.9", dst="1.2.3.4")
        / TCP(sport=55000, dport=443)
        / Raw(b"\x16\x03"),
    )
    assert parse(pkt).hostname == ""


def test_dhcp_hostname_option_is_extracted_with_lease_owner():
    payload = _dhcp_packet(name="gaming-rig", yiaddr="192.168.1.50")
    pkt = make(
        Ether() / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / Raw(payload),
    )
    ev = parse(pkt)
    assert ev.hostname == "gaming-rig"
    assert ev.hostname_ip == "192.168.1.50"  # lease holder, not 0.0.0.0


def test_dhcp_without_magic_cookie_is_ignored():
    payload = _dhcp_packet(name="gaming-rig", yiaddr="192.168.1.50", magic=False)
    pkt = make(
        Ether() / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / Raw(payload),
    )
    assert parse(pkt).hostname == ""


def test_dhcp_selection_only_on_dhcp_ports():
    payload = _dhcp_packet(name="gaming-rig", yiaddr="192.168.1.50")
    pkt = make(
        Ether() / IP(src="10.0.0.9", dst="10.0.0.1") / UDP(sport=50000, dport=50000) / Raw(payload),
    )
    assert parse(pkt).hostname == ""


def _dhcp_packet(name: str, yiaddr: str = "0.0.0.0", magic: bool = True) -> bytes:
    """Handcraft a DHCPDISCOVER/REQUEST payload with a host-name option."""
    fixed = (
        b"\x01\x01\x06\x00"
        + bytes(4)  # xid
        + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00"  # ciaddr
        + bytes(map(int, yiaddr.split(".")))  # yiaddr
        + bytes(4)
        + bytes(4)  # siaddr, giaddr
        + bytes(16)  # chaddr
        + bytes(64)  # sname
        + bytes(128)  # file
    )
    option = b"\x0c" + bytes([len(name)]) + name.encode() + b"\xff"
    suffix = b"\x63\x82\x53\x63" if magic else bytes(4)
    return fixed + suffix + option


def test_dhcp_hostname_length_and_charset_are_enforced():
    sneaky = "bad name; drop table"[:16].encode()
    payload = (
        b"\x01\x01\x06\x00"
        + bytes(4)
        + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + bytes(4)
        + bytes(4)
        + bytes(16)
        + bytes(64)
        + bytes(128)
        + b"\x63\x82\x53\x63"
        + b"\x0c"
        + bytes([len(sneaky)])
        + sneaky
        + b"\xff"
    )
    pkt = make(
        Ether() / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / Raw(payload),
    )
    assert parse(pkt).hostname == ""
