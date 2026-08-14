"""Plaintext-detector tests using synthetic events / raw frames."""

import pytest

from panopticon.core.event import PacketEvent
from panopticon.core.store import StateStore
from panopticon.detection.base import DetectorEngine
from panopticon.detection.plaintext import PlaintextDetector


def ev(t, src="10.0.0.1", dst="8.8.8.8", sport=40000, dport=80,
       service="http", proto="tcp"):
    return PacketEvent(t, src, dst, proto, sport, dport, 100, service)


def test_port_based_plaintext_warn():
    detector = PlaintextDetector()
    alert = detector.process_event(ev(1.0), 1.0)
    assert alert is not None
    assert alert.kind == "plaintext"
    assert alert.severity == "warn"
    assert "http" in alert.summary


def test_source_port_based_plaintext():
    detector = PlaintextDetector()
    alert = detector.process_event(
        ev(1.0, sport=21, dport=50000, service="ephemeral"), 1.0,
    )
    assert alert is not None
    assert "ftp" in alert.summary


def test_credential_marker_warn():
    detector = PlaintextDetector()
    alert = detector.process_event(
        ev(1.0, dport=443, service="https"),
        1.0,
        raw=b"USER alice\r\nPASS secret\r\n",
    )
    assert alert is not None
    assert alert.kind == "plaintext"
    assert alert.severity == "warn"


def test_authorization_marker_warn():
    detector = PlaintextDetector()
    alert = detector.process_event(
        ev(1.0, dport=443, service="https"),
        1.0,
        raw=b"Authorization: Basic dXNlcjpwYXNz",
    )
    assert alert is not None
    assert alert.severity == "warn"


def test_http_verb_marker_info():
    detector = PlaintextDetector()
    alert = detector.process_event(
        ev(1.0, dport=443, service="https"),
        1.0,
        raw=b"GET /index.html HTTP/1.1",
    )
    assert alert is not None
    assert alert.severity == "info"


def test_no_plaintext_no_marker_no_alert():
    detector = PlaintextDetector()
    assert detector.process_event(
        ev(1.0, dport=443, service="https"), 1.0, raw=b"\x00\x01\x02garbage",
    ) is None


def test_payload_gate_requires_marker():
    gated = PlaintextDetector(payload_gate=True)
    assert gated.process_event(ev(1.0, dport=80), 1.0, raw=b"no markers") is None
    alert = gated.process_event(
        ev(1.0, dport=80), 1.0, raw=b"GET /index HTTP/1.1",
    )
    assert alert is not None
    assert alert.severity == "warn"


def test_scan_is_limited_to_head_bytes():
    detector = PlaintextDetector(max_scan_bytes=8)
    assert detector.process_event(
        ev(1.0, dport=443, service="https"),
        1.0,
        raw=b"abcdefghGET /index HTTP/1.1",
    ) is None


def test_engine_dedups_plaintext_per_source():
    store = StateStore()
    engine = DetectorEngine(
        store,
        detectors=[PlaintextDetector()],
        cooldown=30.0,
    )
    assert engine.process_event(ev(1.0), 1.0) is not None
    # Same source, different target: suppressed by the 30s cooldown.
    assert engine.process_event(ev(2.0, dst="9.9.9.9"), 2.0) is None
    assert len(store.snapshot_alerts()) == 1
    # A different source alerts independently.
    assert engine.process_event(ev(3.0, src="10.0.0.2"), 3.0) is not None
    assert len(store.snapshot_alerts()) == 2
