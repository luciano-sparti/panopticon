"""Plaintext-detector tests using synthetic events with payload bytes.

The detector reads the transport payload that the parser pre-extracts onto
``PacketEvent.payload`` — it never dissects the raw frame itself.
"""

from panopticon.core.event import PacketEvent
from panopticon.core.store import StateStore
from panopticon.detection.base import DetectorEngine
from panopticon.detection.plaintext import PlaintextDetector


def ev(
    t,
    src="10.0.0.1",
    dst="8.8.8.8",
    sport=40000,
    dport=80,
    service="http",
    proto="tcp",
    payload=b"",
):
    return PacketEvent(t, src, dst, proto, sport, dport, 100, service, payload=payload)


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
        ev(1.0, sport=21, dport=50000, service="ephemeral"),
        1.0,
    )
    assert alert is not None
    assert "ftp" in alert.summary


def test_source_port_plaintext_reports_matching_port_and_direction():
    detector = PlaintextDetector()
    alert = detector.process_event(
        ev(1.0, sport=21, dport=54321, service="ephemeral"),
        1.0,
    )
    assert alert is not None
    assert "port 21" in alert.summary
    assert "from" in alert.summary
    assert "54321" not in alert.summary


def test_destination_port_plaintext_reports_direction():
    detector = PlaintextDetector()
    alert = detector.process_event(ev(1.0, dport=80), 1.0)
    assert alert is not None
    assert "port 80" in alert.summary
    assert "to" in alert.summary


def test_no_port_hit_or_payload_is_noop():
    detector = PlaintextDetector()
    assert detector.process_event(ev(1.0, dport=443, service="https"), 1.0) is None
    # Port tier still fires without payload.
    assert detector.process_event(ev(2.0, dport=80, service="http"), 2.0) is not None


def test_payload_marker_found_in_event_payload():
    detector = PlaintextDetector()
    alert = detector.process_event(
        ev(1.0, dport=443, service="https", payload=b"GET /secret HTTP/1.1\r\n"),
        1.0,
    )
    assert alert is not None
    assert alert.severity == "info"


def test_ip_header_bytes_are_not_part_of_payload():
    detector = PlaintextDetector()
    # The raw head can contain b"GET /" (e.g. inside an IPv4 header), but
    # only the transport payload carried on the event is scanned.
    event = ev(1.0, dport=443, service="https", payload=b"no markers")
    assert detector.process_event(event, 1.0, raw=b"GET /") is None


def test_payload_scan_budget_applies_to_payload_only():
    detector = PlaintextDetector(max_scan_bytes=8)
    event = ev(1.0, dport=443, service="https", payload=b"abcdefghGET /x")
    assert detector.process_event(event, 1.0) is None


def test_credential_marker_warn():
    detector = PlaintextDetector()
    alert = detector.process_event(
        ev(1.0, dport=443, service="https", payload=b"USER alice\r\nPASS secret\r\n"),
        1.0,
    )
    assert alert is not None
    assert alert.kind == "plaintext"
    assert alert.severity == "warn"


def test_authorization_marker_warn():
    detector = PlaintextDetector()
    alert = detector.process_event(
        ev(1.0, dport=443, service="https", payload=b"Authorization: Basic dXNlcjpwYXNz"),
        1.0,
    )
    assert alert is not None
    assert alert.severity == "warn"


def test_http_verb_marker_info():
    detector = PlaintextDetector()
    alert = detector.process_event(
        ev(1.0, dport=443, service="https", payload=b"GET /index.html HTTP/1.1"),
        1.0,
    )
    assert alert is not None
    assert alert.severity == "info"


def test_no_plaintext_no_marker_no_alert():
    detector = PlaintextDetector()
    assert (
        detector.process_event(
            ev(1.0, dport=443, service="https", payload=b"\x00\x01\x02garbage"),
            1.0,
        )
        is None
    )


def test_scan_is_limited_to_head_bytes():
    detector = PlaintextDetector(max_scan_bytes=8)
    assert (
        detector.process_event(
            ev(1.0, dport=443, service="https", payload=b"abcdefghGET /index HTTP/1.1"),
            1.0,
        )
        is None
    )


def test_multiple_markers_first_wins():
    detector = PlaintextDetector()
    alert = detector.process_event(
        ev(1.0, dport=443, service="https", payload=b"PASS x\r\nGET /y"),
        1.0,
    )
    assert alert is not None
    assert "PASS" in alert.summary


def test_engine_dedups_plaintext_per_source():
    store = StateStore()
    engine = DetectorEngine(
        store,
        detectors=[PlaintextDetector()],
        cooldown=30.0,
    )
    assert engine.process_event(ev(1.0), 1.0) != []
    # Same source, different target: suppressed by the 30s cooldown.
    assert engine.process_event(ev(2.0, dst="9.9.9.9"), 2.0) == []
    assert len(store.snapshot_alerts()) == 1
    # A different source alerts independently.
    assert engine.process_event(ev(3.0, src="10.0.0.2"), 3.0) != []
    assert len(store.snapshot_alerts()) == 2
