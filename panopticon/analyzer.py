"""Panopticon CLI entry point (Phase 2 wiring).

Starts the sniffer + pipeline worker + streaming exporters, maintains the
state store, and shuts everything down gracefully on SIGINT/SIGTERM: the
sniffer socket is closed, the queue is drained, and exporters are flushed.
The Rich dashboard and q-to-quit land in Phase 4.

Clock contract: alert dedup (``DetectorEngine``), detector TTL pruning, and
the state-store talker TTL all assume a single consistent clock. Live
captures satisfy this because ``PacketEvent.timestamp`` (epoch, from
``pkt.time``) and the prune wall clock are the same time base; the prune
loop passes one ``now`` to every prune call so they stay consistent with
each other. Synthetic/replayed feeds must put ``event.timestamp`` on a
single monotonic clock (and use the same ``now`` for pruning) so that state
is not purged out from under the pipeline.
"""

from __future__ import annotations

import argparse
import queue
import signal
import sys
import threading
import time
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
    try:
        exporters = [
            PcapExportWriter(args.export_pcap),
            CsvExportWriter(args.export_csv),
        ]
    except OSError as exc:
        print(
            f"panopticon: could not open export files "
            f"({args.export_pcap}, {args.export_csv}): {exc}",
            file=sys.stderr,
        )
        return 2
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

    reported_worker_errors = 0
    try:
        while not shutdown.is_set():
            shutdown.wait(args.refresh)
            now = time.time()
            if sniffer.capture_failed:
                reason = sniffer.exception
                message = "capture stopped unexpectedly"
                if reason is not None:
                    message += f" ({reason})"
                print(f"panopticon: {message}.", file=sys.stderr)
                break
            if worker.error_count > reported_worker_errors:
                print(
                    f"panopticon: pipeline error: {worker.last_error}",
                    file=sys.stderr,
                )
                reported_worker_errors = worker.error_count
            store.prune(now)
            worker.prune(now)
    except KeyboardInterrupt:
        pass
    finally:
        shutdown.set()
        sniffer.stop()
        sniffer.join(timeout=5)
        worker.stop()
        worker.join()
        drained = worker.drain()
        worker.flush()
        for exporter in exporters:
            exporter.close()

    telemetry = store.snapshot_telemetry()
    print(
        f"panopticon: stopped — {telemetry['total_packets']} packets, "
        f"{telemetry['dropped_packets']} dropped, {drained} drained, "
        f"{telemetry['alerts_total']} alerts, "
        f"exports: {args.export_pcap}, {args.export_csv}"
    )
    for alert in store.snapshot_alerts():
        print(f"  [{alert.severity}] {alert.kind}: {alert.summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
