"""Export writer tests (no root / live capture needed)."""

import csv
import json

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import rdpcap

from panopticon.core.event import AlertEvent, PacketEvent
from panopticon.export.alert_writer import AlertExportWriter
from panopticon.export.csv_writer import CSV_FIELDNAMES, CsvExportWriter
from panopticon.export.pcap_writer import PcapExportWriter


def ev(timestamp, src="10.0.0.1", dst="8.8.8.8", proto="tcp", sport=1000, dport=80, size=100):
    return PacketEvent(timestamp, src, dst, proto, sport, dport, size, "http")


def frame():
    p = Ether() / IP(src="10.0.0.1", dst="8.8.8.8") / TCP(sport=1000, dport=80)
    p.time = 100.0
    return bytes(p)


def test_pcap_writer_round_trip(tmp_path):
    path = tmp_path / "out.pcap"
    writer = PcapExportWriter(str(path))
    for i in range(5):
        writer.write(frame(), ev(float(i)))
    writer.flush()
    writer.close()

    pkts = rdpcap(str(path))
    assert len(pkts) == 5
    assert pkts[0][TCP].dport == 80
    assert pkts[0][IP].src == "10.0.0.1"


def test_pcap_writer_flushes_on_packet_threshold(tmp_path):
    path = tmp_path / "out.pcap"
    writer = PcapExportWriter(str(path), flush_every=2, flush_bytes=10**9)
    writer.write(frame(), ev(0.0))
    assert writer._count == 1
    writer.write(frame(), ev(1.0))
    assert writer._count == 0
    writer.close()
    assert len(rdpcap(str(path))) == 2


def test_pcap_writer_flushes_on_byte_threshold(tmp_path):
    path = tmp_path / "out.pcap"
    size = len(frame())
    writer = PcapExportWriter(str(path), flush_every=10**9, flush_bytes=size)
    writer.write(frame(), ev(0.0))
    assert writer._count == 0  # byte threshold reached on the first write
    writer.close()


def test_pcap_writer_appends_across_runs(tmp_path):
    path = tmp_path / "out.pcap"
    w1 = PcapExportWriter(str(path))
    w1.write(frame(), ev(0.0))
    w1.close()
    w2 = PcapExportWriter(str(path))
    w2.write(frame(), ev(1.0))
    w2.close()
    pkts = rdpcap(str(path))
    assert len(pkts) == 2


def test_pcap_writer_infers_linktype_from_raw_ip_frame(tmp_path):
    path = tmp_path / "raw.pcap"
    p = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1, dport=80)
    p.time = 100.0
    writer = PcapExportWriter(str(path))
    writer.write(bytes(p), ev(0.0))
    writer.close()
    pkts = rdpcap(str(path))
    assert len(pkts) == 1
    assert pkts[0].haslayer(IP)


def test_pcap_writer_respects_explicit_linktype(tmp_path):
    path = tmp_path / "out.pcap"
    writer = PcapExportWriter(str(path), linktype=1)
    writer.write(frame(), ev(0.0))
    writer.close()
    assert len(rdpcap(str(path))) == 1


def test_csv_writer_writes_header_and_rows(tmp_path):
    path = tmp_path / "out.csv"
    writer = CsvExportWriter(str(path))
    writer.write(frame(), ev(100.0))
    writer.write(frame(), ev(101.0))
    writer.flush()
    writer.close()

    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert list(rows[0].keys()) == CSV_FIELDNAMES
    assert len(rows) == 2
    assert rows[0]["src"] == "10.0.0.1"
    assert rows[0]["dport"] == "80"
    assert rows[0]["service"] == "http"
    assert rows[0]["ts"] == "100.0"
    assert rows[0]["size"] == "100"


def test_csv_writer_flushes_on_row_threshold(tmp_path):
    path = tmp_path / "out.csv"
    writer = CsvExportWriter(str(path), flush_every=3)
    for i in range(3):
        writer.write(frame(), ev(float(i)))
    assert writer._count == 0
    writer.close()


def test_csv_writer_appends_across_runs(tmp_path):
    path = tmp_path / "out.csv"
    w1 = CsvExportWriter(str(path))
    w1.write(frame(), ev(0.0))
    w1.close()
    w2 = CsvExportWriter(str(path))
    w2.write(frame(), ev(1.0))
    w2.close()
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 2
    assert rows[0]["ts"] == "0.0"
    assert rows[1]["ts"] == "1.0"


def test_csv_writer_writes_single_header_on_new_file(tmp_path):
    path = tmp_path / "out.csv"
    w = CsvExportWriter(str(path))
    w.close()
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 0


def test_alert_writer_round_trip(tmp_path):
    path = tmp_path / "alerts.jsonl"
    writer = AlertExportWriter(str(path))
    writer.write_alert(AlertEvent(1.0, "info", "high_port", "port 50000", "10.0.0.1", "8.8.8.8"))
    writer.write_alert(AlertEvent(2.0, "warn", "plaintext", "ftp creds", "10.0.0.2", "8.8.8.8"))
    writer.flush()
    writer.close()

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["kind"] == "high_port"
    assert first["severity"] == "info"
    assert first["summary"] == "port 50000"
    assert first["src"] == "10.0.0.1"
    assert first["dst"] == "8.8.8.8"


def test_alert_writer_appends_across_runs(tmp_path):
    path = tmp_path / "alerts.jsonl"
    w1 = AlertExportWriter(str(path))
    w1.write_alert(AlertEvent(1.0, "info", "syn_scan", "scan", "1.1.1.1", "2.2.2.2"))
    w1.close()
    w2 = AlertExportWriter(str(path))
    w2.write_alert(AlertEvent(2.0, "warn", "high_port", "port", "3.3.3.3", "4.4.4.4"))
    w2.close()

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[1])["kind"] == "high_port"


def test_alert_writer_flushes_on_threshold(tmp_path):
    path = tmp_path / "alerts.jsonl"
    writer = AlertExportWriter(str(path), flush_every=2)
    writer.write_alert(AlertEvent(1.0, "info", "x", "y", "1.1.1.1", "2.2.2.2"))
    writer.write_alert(AlertEvent(2.0, "info", "x", "y", "1.1.1.1", "2.2.2.2"))
    writer.close()
    assert len(path.read_text(encoding="utf-8").splitlines()) == 2
