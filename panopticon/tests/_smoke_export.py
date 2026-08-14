"""Smoke harness: round-trip raw frames through the PCAP + CSV exporters.

Run via:  python -m panopticon.tests._smoke_export
No root required. Writes synthetic frames with the real exporters, then reads
the files back to confirm they are valid and complete.
"""
from __future__ import annotations

import csv
import os
import tempfile

from scapy.all import Ether, IP, TCP, Raw, rdpcap

from panopticon.core.event import PacketEvent
from panopticon.core.parser import parse
from panopticon.export.pcap_writer import PcapExportWriter
from panopticon.export.csv_writer import CsvExportWriter


def _frames():
    frames = []
    for i in range(5):
        frames.append(
            bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
                  TCP(sport=12345, dport=443, flags="PA") /
                  Raw(f"hello {i}".encode()))
        )
    return frames


def main() -> None:
    # Fresh temp dir each run so the test is idempotent (exporters append).
    out = tempfile.mkdtemp(prefix="panopticon-smoke-")
    try:
        pcap_path = os.path.join(out, "session.pcap")
        csv_path = os.path.join(out, "session.csv")

        frames = _frames()
        events = [parse(Ether(f)) for f in frames]

        pcap = PcapExportWriter(pcap_path, flush_every=2, flush_bytes=1 << 20)
        csvw = CsvExportWriter(csv_path, flush_every=2)
        for raw, ev in zip(frames, events):
            pcap.write(raw, ev)
            csvw.write(raw, ev)
        pcap.close()
        csvw.close()

        # Re-read PCAP
        pkts = rdpcap(pcap_path)
        assert len(pkts) == len(frames), f"pcap round-trip: {len(pkts)} != {len(frames)}"

        # Re-read CSV
        with open(csv_path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        assert len(rows) == len(frames), f"csv rows: {len(rows)} != {len(frames)}"
        assert rows[0]["dport"] == "443", f"unexpected csv row: {rows[0]}"

        print(f"export smoke OK: pcap={len(pkts)} pkts, csv={len(rows)} rows, "
              f"files valid")
    finally:
        import shutil
        shutil.rmtree(out, ignore_errors=True)


if __name__ == "__main__":
    main()
