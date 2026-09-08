"""Pipeline worker tests using synthetic events (no root / live capture)."""

import csv
import json
import queue
import time

from scapy.utils import rdpcap

from panopticon.core.event import AlertEvent, PacketEvent
from panopticon.core.store import StateStore
from panopticon.detection.base import BaseDetector, DetectorEngine
from panopticon.detection.high_port import HighPortDetector
from panopticon.detection.syn_scan import SynScanDetector
from panopticon.export.alert_writer import AlertExportWriter
from panopticon.export.base import BaseExporter
from panopticon.export.csv_writer import CsvExportWriter
from panopticon.export.pcap_writer import PcapExportWriter
from panopticon.pipeline import PipelineWorker


def ev(
    timestamp, src="10.0.0.1", dst="8.8.8.8", proto="tcp", sport=1000, dport=80, size=100, flags=""
):
    return PacketEvent(timestamp, src, dst, proto, sport, dport, size, "http", flags)


def wait_until(cond, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.01)
    return cond()


class RecordingDetector(BaseDetector):
    def __init__(self):
        self.seen = []
        self.raws = []

    def process_event(self, event, now, raw=None):
        self.seen.append(event)
        self.raws.append(raw)


class RaisingExporter(BaseExporter):
    """Simulates a disk-full / broken exporter."""

    def write(self, raw, event):
        raise OSError("disk full")

    def flush(self):
        pass

    def close(self):
        pass


def test_worker_updates_state_store():
    q = queue.Queue()
    store = StateStore()
    worker = PipelineWorker(q, store)
    worker.start()
    try:
        for i in range(5):
            q.put((b"\x00" * 60, ev(float(i), src=f"10.0.0.{i + 1}")))
        assert wait_until(lambda: store.snapshot_telemetry()["total_packets"] == 5)
        tele = store.snapshot_telemetry()
        assert tele["total_bytes"] == 5 * 100
        assert tele["unique_hosts"] == 5
        assert len(store.snapshot_stream()) == 5
        assert store.snapshot_stream()[0].src == "10.0.0.1"
    finally:
        worker.stop()
        worker.join(timeout=2)
        worker.drain()


def test_worker_feeds_detector_synchronously():
    q = queue.Queue()
    detector = RecordingDetector()
    worker = PipelineWorker(q, StateStore(), detector=detector)
    for i in range(4):
        q.put((b"\x00" * 60, ev(float(i))))
    worker.drain()
    assert [e.timestamp for e in detector.seen] == [0.0, 1.0, 2.0, 3.0]
    assert detector.raws == [b"\x00" * 60] * 4


def test_engine_without_detectors_is_noop():
    store = StateStore()
    engine = DetectorEngine(store)
    assert engine.process_event(ev(0.0)) == []
    assert engine.prune(now=0.0) == 0


def test_worker_alerts_land_in_state_store():
    q = queue.Queue()
    store = StateStore()
    engine = DetectorEngine(
        store,
        detectors=[SynScanDetector(threshold=1)],
    )
    worker = PipelineWorker(q, store, detector=engine)
    for i in range(3):
        q.put((b"\x00" * 60, ev(float(i), dport=1000 + i, flags="S")))
    worker.drain()
    alerts = store.snapshot_alerts()
    assert len(alerts) == 1
    assert alerts[0].kind == "syn_scan"
    assert store.snapshot_telemetry()["alerts_total"] == 1


def test_drain_processes_pending_items_without_thread():
    q = queue.Queue()
    store = StateStore()
    worker = PipelineWorker(q, store)
    for i in range(10):
        q.put((b"\x00" * 60, ev(float(i), src=f"ip{i}")))
    assert worker.drain() == 10
    assert q.empty()
    assert store.snapshot_telemetry()["total_packets"] == 10


def test_drain_on_empty_queue_returns_zero():
    worker = PipelineWorker(queue.Queue(), StateStore())
    assert worker.drain() == 0


def test_worker_writes_valid_pcap_and_csv(tmp_path):
    pcap_path = tmp_path / "session.pcap"
    csv_path = tmp_path / "session.csv"
    exporters = [
        PcapExportWriter(str(pcap_path)),
        CsvExportWriter(str(csv_path)),
    ]
    q = queue.Queue()
    store = StateStore()
    worker = PipelineWorker(q, store, exporters=exporters)
    for i in range(3):
        q.put((b"\x00" * 64, ev(float(i))))
    worker.drain()
    worker.flush()
    for exporter in exporters:
        exporter.close()

    pkts = rdpcap(str(pcap_path))
    assert len(pkts) == 3

    with open(csv_path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 3
    assert rows[0]["src"] == "10.0.0.1"
    assert rows[0]["dport"] == "80"
    assert rows[2]["ts"] == "2.0"


def test_worker_survives_raising_exporter():
    q = queue.Queue()
    store = StateStore()
    worker = PipelineWorker(q, store, exporters=[RaisingExporter()])
    worker.start()
    try:
        q.put((b"\x00" * 60, ev(0.0)))
        assert wait_until(lambda: worker.error_count >= 1)
        assert worker.is_alive()
        # The worker is still alive and keeps processing the queue.
        q.put((b"\x00" * 60, ev(1.0)))
        assert wait_until(lambda: worker.error_count >= 2)
        assert store.snapshot_telemetry()["total_packets"] >= 2
        assert worker.last_error == "OSError: disk full"
    finally:
        worker.stop()
        worker.join(timeout=2)


def test_drain_contains_exporter_errors():
    q = queue.Queue()
    for i in range(3):
        q.put((b"\x00" * 60, ev(float(i))))
    worker = PipelineWorker(q, StateStore(), exporters=[RaisingExporter()])
    assert worker.drain() == 3
    assert worker.error_count == 3
    assert q.empty()


def test_worker_export_alerts_to_alert_writer(tmp_path):
    q = queue.Queue()
    store = StateStore()
    alert_path = tmp_path / "alerts.jsonl"
    worker = PipelineWorker(
        q,
        store,
        detector=DetectorEngine(
            store,
            detectors=[HighPortDetector(threshold_port=1000)],
        ),
        alert_exporter=AlertExportWriter(str(alert_path)),
    )
    for i in range(3):
        q.put((b"\x00" * 60, ev(float(i), dport=50000)))
    worker.drain()
    worker.flush()

    lines = alert_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    first = json.loads(lines[0])
    assert first["kind"] == "high_port"
    assert first["summary"] == "connection to high/registered destination port 50000"
    assert store.snapshot_telemetry()["alerts_total"] == 1


def test_worker_exports_all_alerts_per_packet(tmp_path):
    q = queue.Queue()
    store = StateStore()
    alert_path = tmp_path / "alerts.jsonl"

    class KindADetector(BaseDetector):
        engine_cooldown = 0.0

        def process_event(self, event, now, raw=None):
            return AlertEvent(
                time=event.timestamp,
                severity="warn",
                kind="kind_a",
                summary="a",
                src=event.src,
                dst=event.dst,
            )

    class KindBDetector(BaseDetector):
        engine_cooldown = 0.0

        def process_event(self, event, now, raw=None):
            return AlertEvent(
                time=event.timestamp,
                severity="warn",
                kind="kind_b",
                summary="b",
                src=event.src,
                dst=event.dst,
            )

    worker = PipelineWorker(
        q,
        store,
        detector=DetectorEngine(store, detectors=[KindADetector(), KindBDetector()]),
        alert_exporter=AlertExportWriter(str(alert_path)),
    )
    q.put((b"\x00" * 60, ev(0.0)))
    worker.drain()
    worker.flush()

    lines = alert_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    kinds = {json.loads(line)["kind"] for line in lines}
    assert kinds == {"kind_a", "kind_b"}
    assert store.snapshot_telemetry()["alerts_total"] == 2


def test_worker_alert_exporter_errors_are_contained(tmp_path):
    q = queue.Queue()
    tmp_path / "alerts.jsonl"

    class RaisingAlertExporter:
        def write_alert(self, alert):
            raise OSError("disk full")

        def flush(self):
            pass

        def close(self):
            pass

    worker = PipelineWorker(
        q,
        StateStore(),
        detector=DetectorEngine(
            StateStore(),
            detectors=[HighPortDetector(threshold_port=1000)],
        ),
        alert_exporter=RaisingAlertExporter(),
    )
    q.put((b"\x00" * 60, ev(0.0, dport=50000)))
    worker.start()
    try:
        assert wait_until(lambda: worker.error_count >= 1)
        assert worker.is_alive()
    finally:
        worker.stop()
        worker.join(timeout=2)
