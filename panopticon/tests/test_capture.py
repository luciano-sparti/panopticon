"""Capture module tests without live sniffing or root privileges."""

import os
import queue
import time

import pytest
from scapy.arch import get_if_list
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


def wait_until(cond, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.01)
    return cond()


def test_auto_detect_skips_pseudo_and_loopback(monkeypatch):
    monkeypatch.setattr(
        "panopticon.capture.sniffer.get_if_list",
        lambda: ["lo", "docker0", "utun0", "vmnet1", "vboxnet0", "wg0", "eth0"],
    )
    assert auto_detect_interface() == "eth0"


def test_auto_detect_falls_back_to_first_when_all_pseudo(monkeypatch):
    monkeypatch.setattr(
        "panopticon.capture.sniffer.get_if_list",
        lambda: ["lo", "ppp0", "tap0"],
    )
    assert auto_detect_interface() == "lo"


def test_sniffer_running_mirrors_underlying_state():
    if not get_if_list():
        pytest.skip("no network interfaces to attempt capture on")
    q = queue.Queue()
    sniffer = Sniffer("lo", q, StateStore())
    sniffer.start()
    try:
        # Wait until the underlying AsyncSniffer has either started
        # capturing or failed (e.g. no root privileges).
        assert wait_until(
            lambda: sniffer._sniffer.running
            or sniffer._sniffer.exception is not None
        )
        # The liveness probe must reflect the underlying sniffer, not the
        # short-lived wrapper thread.
        assert sniffer.running == bool(sniffer._sniffer.running)
        if sniffer._sniffer.exception is not None:
            assert sniffer.capture_failed
    finally:
        sniffer.stop()
        sniffer.join(timeout=2)


def test_sniffer_failure_surfaces_exception():
    if not get_if_list():
        pytest.skip("no network interfaces to attempt capture on")
    if os.geteuid() == 0:
        pytest.skip("running as root; cannot force a capture permission error")
    q = queue.Queue()
    sniffer = Sniffer("lo", q, StateStore())
    sniffer.start()
    try:
        # scapy 2.7 leaves AsyncSniffer.running stuck True and records the
        # failure in .exception; the exception is the authoritative probe.
        assert wait_until(lambda: sniffer._sniffer.exception is not None)
        assert sniffer.exception is sniffer._sniffer.exception
        assert sniffer.capture_failed
    finally:
        sniffer.stop()
        sniffer.join(timeout=2)
