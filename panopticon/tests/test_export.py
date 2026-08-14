"""Export writer tests (no root / live capture needed)."""

import csv

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import rdpcap

from panopticon.core.event import PacketEvent
from panopticon.export.csv_writer import CSV_FIELDNAMES, CsvExportWriter
from panopticon.export.pcap_writer import PcapExportWriter


def ev(timestamp, src="10.0.0.1", dst="8.8.8.8", proto="tcp",
       sport=1000, dport=80, size=100):
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
