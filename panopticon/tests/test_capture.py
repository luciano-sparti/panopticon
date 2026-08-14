"""Capture module tests without live sniffing or root privileges."""

import queue

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from panopticon.capture import (
    Sniffer,
    auto_detect_interface,
    handle_packet,
    preflight,
)
from panopticon.capture.sniffer import (
    _cap_net_raw_enabled,
    _privilege_problem,
)
from panopticon.core.store import StateStore


def pkt(time=100.0):
    p = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff")
        / IP(src="1.2.3.4", dst="5.6.7.8")
        / TCP(sport=1111, dport=443, flags="S")
        / Raw(b"x")
    )
    p.time = time
    return p


def test_auto_detect_returns_string():
    assert isinstance(auto_detect_interface(), str)


def test_preflight_returns_verdict_string():
    assert isinstance(preflight(""), str)


def test_preflight_rejects_unknown_interface():
    assert preflight("definitely-not-an-iface-xyz")


def test_handle_packet_parses_and_enqueues():
    q = queue.Queue()
    store = StateStore()
    handle_packet(q, store, pkt())
    raw, event = q.get_nowait()
    assert event.src == "1.2.3.4"
    assert event.dst == "5.6.7.8"
    assert event.proto == "tcp"
    assert event.dport == 443
    assert event.service == "https"
    assert event.timestamp == 100.0
    assert raw == bytes(pkt())
    assert store.snapshot_telemetry()["dropped_packets"] == 0


def test_handle_packet_counts_dropped_when_queue_full():
    q = queue.Queue(maxsize=1)
    store = StateStore()
    q.put_nowait((b"stale", None))
    handle_packet(q, store, pkt())
    assert store.snapshot_telemetry()["dropped_packets"] == 1
    assert q.qsize() == 1
    assert q.queue[0][0] == b"stale"


def test_handle_packet_skips_none():
    q = queue.Queue()
    store = StateStore()
    handle_packet(q, store, None)
    assert q.empty()
    assert store.snapshot_telemetry()["total_packets"] == 0


def test_privilege_problem_returns_string():
    assert isinstance(_privilege_problem(), str)


def test_cap_net_raw_helper_returns_bool():
    assert isinstance(_cap_net_raw_enabled(), bool)


def test_sniffer_construction_is_lazy():
    sniffer = Sniffer("lo", queue.Queue(), StateStore(), bpf_filter="tcp")
    assert sniffer.interface == "lo"
    assert not sniffer.running
    sniffer.stop()
