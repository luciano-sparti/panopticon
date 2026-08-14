"""Panopticon CLI entry point (Phase 2 wiring).

Starts the sniffer + pipeline worker + streaming exporters, maintains the
state store, and shuts everything down gracefully on SIGINT/SIGTERM: the
sniffer socket is closed, the queue is drained, and exporters are flushed.
The Rich dashboard and q-to-quit land in Phase 4.
"""

from __future__ import annotations

import argparse
import queue
import signal
import sys
import threading
from typing import List, Optional

from panopticon.capture import Sniffer, auto_detect_interface, preflight
from panopticon.core.store import StateStore
from panopticon.detection import (
    DetectorEngine,
    HighPortDetector,
    PlaintextDetector,
    SynScanDetector,
)
from panopticon.export import CsvExportWriter, PcapExportWriter
from panopticon.pipeline import PipelineWorker

DEFAULT_REFRESH = 0.5
DEFAULT_QUEUE_SIZE = 10000


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="panopticon",
        description="Terminal real-time network traffic analyzer and mini-NIDS.",
    )
    parser.add_argument(
        "-i",
        "--interface",
        default="",
        help="Network interface to sniff (default: auto-detect)",
    )
    parser.add_argument(
        "--filter",
        default="",
        help='BPF filter, e.g. "tcp or udp" (default: none)',
    )
    parser.add_argument(
        "--refresh",
        type=float,
        default=DEFAULT_REFRESH,
        help="State-maintenance loop interval in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--export-pcap",
        default="session.pcap",
        help="PCAP path for raw frames (default: %(default)s)",
    )
    parser.add_argument(
        "--export-csv",
        default="session.csv",
        help="CSV path for the flow log (default: %(default)s)",
    )
    parser.add_argument(
        "--queue-size",
        type=int,
        default=DEFAULT_QUEUE_SIZE,
        help="Capture queue depth before packets are dropped (default: %(default)s)",
    )
    parser.add_argument(
        "--syn-threshold",
        type=int,
        default=20,
        help="Distinct unresponded SYN targets that trigger a scan alert (default: %(default)s)",
    )
    parser.add_argument(
        "--syn-window",
        type=float,
        default=5.0,
        help="Sliding window (s) for SYN-scan counting (default: %(default)s)",
    )
    parser.add_argument(
        "--high-port",
        type=int,
        default=49152,
        help="Destination ports at/above this value raise high-port alerts (default: %(default)s)",
    )
    parser.add_argument(
        "--alert-cooldown",
        type=float,
        default=30.0,
        help="Min seconds between accepted alerts of the same kind/source (default: %(default)s)",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    interface = args.interface or auto_detect_interface()
    if not interface:
        print(
            "panopticon: no capture interface found (install libpcap/Npcap).",
            file=sys.stderr,
        )
        return 2

    problem = preflight(interface)
    if problem:
        print(f"panopticon: {problem}", file=sys.stderr)
        return 2

    store = StateStore()
    packet_queue: queue.Queue = queue.Queue(maxsize=args.queue_size)
    exporters = [
        PcapExportWriter(args.export_pcap),
        CsvExportWriter(args.export_csv),
    ]
    detector = DetectorEngine(
        store,
        detectors=[
            SynScanDetector(
                threshold=args.syn_threshold,
                window=args.syn_window,
            ),
            PlaintextDetector(),
            HighPortDetector(threshold_port=args.high_port),
        ],
        cooldown=args.alert_cooldown,
    )
    worker = PipelineWorker(
        packet_queue,
        store,
        exporters=exporters,
        detector=detector,
    )
    sniffer = Sniffer(interface, packet_queue, store, bpf_filter=args.filter or None)

    shutdown = threading.Event()

    def _request_shutdown(signum, frame):
        shutdown.set()

    signal.signal(signal.SIGINT, _request_shutdown)
    signal.signal(signal.SIGTERM, _request_shutdown)

    worker.start()
    sniffer.start()
    print(
        f"panopticon: capturing on {interface}"
        + (f" with BPF filter {args.filter!r}" if args.filter else "")
        + " — Ctrl+C to stop"
    )

    try:
        while not shutdown.is_set():
            shutdown.wait(args.refresh)
            store.prune()
            worker.prune()
    except KeyboardInterrupt:
        pass
    finally:
        shutdown.set()
        sniffer.stop()
        sniffer.join(timeout=5)
        worker.stop()
        worker.join(timeout=5)
        drained = worker.drain()
        worker.flush()
        for exporter in exporters:
            exporter.close()

    telemetry = store.snapshot_telemetry()
    print(
        f"panopticon: stopped — {telemetry['total_packets']} packets, "
        f"{telemetry['dropped_packets']} dropped, {drained} drained, "
        f"exports: {args.export_pcap}, {args.export_csv}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
