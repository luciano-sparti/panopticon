"""Pipeline worker tests using synthetic events (no root / live capture)."""

import csv
import queue
import time

from scapy.utils import rdpcap

from panopticon.core.event import PacketEvent
from panopticon.core.store import StateStore
from panopticon.export.csv_writer import CsvExportWriter
from panopticon.export.pcap_writer import PcapExportWriter
from panopticon.pipeline import DetectorEngine, NoopDetector, PipelineWorker


def ev(timestamp, src="10.0.0.1", dst="8.8.8.8", proto="tcp",
       sport=1000, dport=80, size=100):
    return PacketEvent(timestamp, src, dst, proto, sport, dport, size, "http")


def wait_until(cond, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.01)
    return cond()


class RecordingDetector(DetectorEngine):
    def __init__(self):
        self.seen = []

    def analyze(self, event):
        self.seen.append(event)
        return None


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


def test_noop_detector_accepts_everything():
    detector = NoopDetector()
    for i in range(3):
        assert detector.analyze(ev(float(i))) is None


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
