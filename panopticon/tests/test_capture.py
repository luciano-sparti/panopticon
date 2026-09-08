"""Capture module tests without live sniffing or root privileges."""

import os
import queue
import threading
import time
from unittest.mock import patch

import pytest
from scapy.arch import get_if_list
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import AsyncSniffer

from panopticon.capture import (
    Sniffer,
    auto_detect_interface,
    handle_packet,
    preflight,
    validate_bpf_filter,
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


def test_validate_bpf_accepts_empty_and_none():
    assert validate_bpf_filter("eth0", None) == ""
    assert validate_bpf_filter("eth0", "") == ""


def test_validate_bpf_reports_invalid_filter():
    with patch(
        "panopticon.capture.sniffer.conf.L2listen",
        side_effect=RuntimeError("syntax error"),
    ):
        problem = validate_bpf_filter("eth0", "tcp and )")
    assert "invalid BPF filter 'tcp and )'" in problem
    assert "syntax error" in problem


def test_validate_bpf_accepts_compilable_filter(monkeypatch):
    class FakeSocket:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def close(self):
            self.closed = True

    fake = FakeSocket(iface="eth0", filter="tcp")
    monkeypatch.setattr("panopticon.capture.sniffer.conf.L2listen", lambda **kw: fake)
    assert validate_bpf_filter("eth0", "tcp") == ""
    assert fake.closed


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


def test_handle_packet_prefers_original_wire_bytes():
    q = queue.Queue()
    store = StateStore()
    frame = pkt()
    frame.original = b"\x00" * 14 + b"not-what-rebuild-produces"
    handle_packet(q, store, frame)
    raw, event = q.get_nowait()
    assert raw == frame.original
    assert raw != bytes(pkt())
    assert event.src == "1.2.3.4"


def test_handle_packet_counts_queue_drops_when_queue_full():
    q = queue.Queue(maxsize=1)
    store = StateStore()
    q.put_nowait((b"stale", None))
    handle_packet(q, store, pkt())
    telemetry = store.snapshot_telemetry()
    assert telemetry["queue_drops"] == 1
    assert telemetry["parse_failures"] == 0
    assert telemetry["dropped_packets"] == 1
    assert q.qsize() == 1
    assert q.queue[0][0] == b"stale"


def test_handle_packet_counts_parse_failures():
    q = queue.Queue()
    store = StateStore()
    with patch("panopticon.capture.sniffer.parse", side_effect=ValueError("boom")):
        handle_packet(q, store, object())
    telemetry = store.snapshot_telemetry()
    assert telemetry["parse_failures"] == 1
    assert telemetry["queue_drops"] == 0
    assert telemetry["dropped_packets"] == 1
    assert q.empty()


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


def test_sniffer_join_waits_for_real_capture_thread(monkeypatch):
    started = threading.Event()
    release = threading.Event()

    def fake_start(obj, *args, **kwargs):
        thread = threading.Thread(
            target=lambda: (started.set(), release.wait(5), time.sleep(0.3)),
            daemon=True,
        )
        obj.thread = thread
        thread.start()
        return thread

    monkeypatch.setattr(AsyncSniffer, "start", fake_start)
    sniffer = Sniffer("lo", queue.Queue(), StateStore())
    sniffer.start()
    assert started.wait(1.0)

    release.set()
    begin = time.monotonic()
    sniffer.join(timeout=5.0)
    elapsed = time.monotonic() - begin
    # Riding the wrapper thread only would return in ~0s; the fix must also
    # wait for the AsyncSniffer capture loop (which sleeps 0.3s after release).
    assert elapsed >= 0.25
    assert not sniffer._sniffer.thread.is_alive()


def wait_until(cond, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.01)
    return cond()


def _fake_sys_ifaces(monkeypatch, operstate=None, address=None):
    """Fake the sysfs reads so auto-detection needs no real network."""
    monkeypatch.setattr(
        "panopticon.capture.sniffer._iface_operstate",
        lambda name: (operstate or {}).get(name, "unknown"),
    )
    monkeypatch.setattr(
        "panopticon.capture.sniffer._iface_has_address",
        lambda name: (address or {}).get(name, False),
    )


def test_auto_detect_skips_pseudo_and_loopback(monkeypatch):
    monkeypatch.setattr(
        "panopticon.capture.sniffer.get_if_list",
        lambda: ["lo", "docker0", "utun0", "vmnet1", "vboxnet0", "wg0", "eth0"],
    )
    _fake_sys_ifaces(monkeypatch, operstate={"eth0": "up"}, address={"eth0": True})
    assert auto_detect_interface() == "eth0"


def test_auto_detect_falls_back_to_first_when_all_pseudo(monkeypatch):
    monkeypatch.setattr(
        "panopticon.capture.sniffer.get_if_list",
        lambda: ["lo", "ppp0", "tap0"],
    )
    _fake_sys_ifaces(monkeypatch)
    assert auto_detect_interface() == ""


def test_auto_detect_prefers_up_addressed_over_down(monkeypatch):
    monkeypatch.setattr(
        "panopticon.capture.sniffer.get_if_list",
        lambda: ["eno1", "wlp6s0"],
    )
    _fake_sys_ifaces(
        monkeypatch,
        operstate={"eno1": "down", "wlp6s0": "up"},
        address={"eno1": True, "wlp6s0": True},
    )
    assert auto_detect_interface() == "wlp6s0"


def test_auto_detect_prefers_up_addressed_over_up_only(monkeypatch):
    monkeypatch.setattr(
        "panopticon.capture.sniffer.get_if_list",
        lambda: ["eth0", "wlan0"],
    )
    _fake_sys_ifaces(
        monkeypatch,
        operstate={"eth0": "up", "wlan0": "up"},
        address={"eth0": False, "wlan0": True},
    )
    assert auto_detect_interface() == "wlan0"


def test_auto_detect_prefers_up_over_down_without_address(monkeypatch):
    monkeypatch.setattr(
        "panopticon.capture.sniffer.get_if_list",
        lambda: ["eno1", "wlan0"],
    )
    _fake_sys_ifaces(
        monkeypatch,
        operstate={"eno1": "down", "wlan0": "up"},
        address={"eno1": False, "wlan0": False},
    )
    assert auto_detect_interface() == "wlan0"


def test_auto_detect_falls_back_to_any_non_pseudo_when_none_up(monkeypatch):
    monkeypatch.setattr(
        "panopticon.capture.sniffer.get_if_list",
        lambda: ["lo", "eno1", "wlan0"],
    )
    _fake_sys_ifaces(
        monkeypatch,
        operstate={"eno1": "down", "wlan0": "unknown"},
        address={"eno1": False, "wlan0": False},
    )
    assert auto_detect_interface() == "eno1"


def test_auto_detect_excludes_pseudo_even_when_up_addressed(monkeypatch):
    monkeypatch.setattr(
        "panopticon.capture.sniffer.get_if_list",
        lambda: ["lo", "docker0", "wg0"],
    )
    _fake_sys_ifaces(
        monkeypatch,
        operstate={"lo": "up", "docker0": "up", "wg0": "up"},
        address={"lo": True, "docker0": True, "wg0": True},
    )
    assert auto_detect_interface() == ""


def test_auto_detect_returns_empty_when_enumeration_fails(monkeypatch):
    def _boom():
        raise RuntimeError("no libpcap")

    monkeypatch.setattr("panopticon.capture.sniffer.get_if_list", _boom)
    assert auto_detect_interface() == ""


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
            lambda: sniffer._sniffer.running or sniffer._sniffer.exception is not None
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
