"""Tests for the defensive packet parser (no root / live capture needed)."""

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
        Ether() / IP(src="10.0.0.1", dst="8.8.8.8") /
        TCP(sport=40000, dport=80, flags="S") / Raw(b"GET /"),
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


def test_tcp_ephemeral_dport_maps_to_ephemeral_service():
    pkt = make(
        Ether() / IP(src="1.2.3.4", dst="5.6.7.8") /
        TCP(sport=1111, dport=55000, flags="S"),
    )
    ev = parse(pkt)
    assert ev.dport == 55000
    assert ev.service == "ephemeral"


def test_tcp_known_port_maps_to_service():
    pkt = make(
        Ether() / IP(src="1.2.3.4", dst="5.6.7.8") /
        TCP(sport=50000, dport=5432),
    )
    assert parse(pkt).service == "postgres"


def test_udp_dns_parsing():
    pkt = make(
        Ether() / IP(src="192.168.1.5", dst="9.9.9.9") /
        UDP(sport=54321, dport=53),
    )
    ev = parse(pkt)
    assert ev.proto == "udp"
    assert ev.sport == 54321
    assert ev.dport == 53
    assert ev.service == "dns"


def test_icmp_parsing_has_zero_ports():
    pkt = make(
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
        ICMP(type=8, code=0),
    )
    ev = parse(pkt)
    assert ev.proto == "icmp"
    assert ev.sport == 0
    assert ev.dport == 0
    assert ev.service == ""


def test_ipv6_tcp_parsing():
    pkt = make(
        IPv6(src="2001:db8::1", dst="2001:db8::2") /
        TCP(sport=2222, dport=22),
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
        Ether() / IP(src="10.0.0.1", dst="8.8.8.8") /
        TCP(sport=40000, dport=80, flags="S"),
    )
    assert parse(pkt).flags == "S"


def test_tcp_syn_ack_flags_are_parsed():
    pkt = make(
        Ether() / IP(src="8.8.8.8", dst="10.0.0.1") /
        TCP(sport=80, dport=40000, flags="SA"),
    )
    assert parse(pkt).flags == "SA"


def test_non_tcp_flags_are_empty():
    pkt = make(
        Ether() / IP(src="10.0.0.1", dst="8.8.8.8") /
        UDP(sport=50000, dport=53),
    )
    assert parse(pkt).flags == ""
