"""Panopticon CLI entry point (Phases 2 + 4 wiring).

Starts the sniffer + pipeline worker + streaming exporters, maintains the
state store, drives the Rich snapshot dashboard + non-blocking q-to-quit
(``--no-ui`` disables it for headless/CI), and shuts everything down
gracefully on SIGINT/SIGTERM or the ``q`` key: the sniffer socket is closed,
the queue is drained, and exporters are flushed.

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
import json
import os
import queue
import signal
import sys
import threading
import time

from panopticon import __version__
from panopticon.capture import Sniffer, auto_detect_interface, preflight
from panopticon.core.store import StateStore
from panopticon.detection import (
    DetectorEngine,
    HighPortDetector,
    PlaintextDetector,
    SynScanDetector,
)
from panopticon.export import AlertExportWriter, CsvExportWriter, PcapExportWriter
from panopticon.pipeline import PipelineWorker
from panopticon.ui import KeyboardWatcher, UIControls, build_dashboard

DEFAULT_REFRESH = 0.5
DEFAULT_QUEUE_SIZE = 10000


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="panopticon",
        description="Terminal real-time network traffic analyzer and mini-NIDS.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"panopticon {__version__}",
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
    parser.add_argument(
        "--no-ui",
        action="store_true",
        help="Disable the Rich dashboard and keyboard watcher (headless/CI)",
    )
    parser.add_argument(
        "--enable-kill",
        action="store_true",
        help="Enable the scoped k key to SIGTERM the process owning a flow",
    )
    parser.add_argument(
        "--tags-file",
        default="",
        help="JSON {ip: [tags]} path loaded at start and saved on exit",
    )
    parser.add_argument(
        "--export-alerts",
        default="",
        help="JSONL path for detector alerts (default: session.alerts.jsonl)",
    )
    return parser


def _load_tags(store: StateStore, path: str) -> None:
    """Load ``{ip: [tags]}`` JSON into the store (best-effort)."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return
    if not isinstance(data, dict):
        return
    for ip, tags in data.items():
        if not isinstance(tags, list):
            continue
        store.load_tags({str(ip): [t for t in tags if isinstance(t, str)]})


def _save_tags(store: StateStore, path: str) -> None:
    """Persist the tag map as ``{ip: [tags]}`` JSON (best-effort)."""
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(store.snapshot_tags(), fh, indent=2)
    except OSError as exc:
        print(f"panopticon: could not save tags file {path}: {exc}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
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
    if args.tags_file:
        _load_tags(store, args.tags_file)
    packet_queue: queue.Queue = queue.Queue(maxsize=args.queue_size)
    alert_path = args.export_alerts or ""
    if not alert_path:
        pcap_dir = os.path.dirname(os.path.abspath(args.export_pcap))
        alert_path = os.path.join(pcap_dir, "session.alerts.jsonl")
    try:
        exporters = [
            PcapExportWriter(args.export_pcap),
            CsvExportWriter(args.export_csv),
        ]
        alert_exporter = AlertExportWriter(alert_path)
    except OSError as exc:
        print(
            f"panopticon: could not open export files "
            f"({args.export_pcap}, {args.export_csv}, {alert_path}): {exc}",
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
        alert_exporter=alert_exporter,
    )
    sniffer = Sniffer(interface, packet_queue, store, bpf_filter=args.filter or None)

    shutdown = threading.Event()
    keyboard_stop = threading.Event()

    def _request_shutdown(signum, frame):
        shutdown.set()

    signal.signal(signal.SIGINT, _request_shutdown)
    signal.signal(signal.SIGTERM, _request_shutdown)

    worker.start()
    sniffer.start()
    controls = UIControls(store, enable_kill=args.enable_kill)
    keyboard = None
    if not args.no_ui:
        keyboard = KeyboardWatcher(keyboard_stop, on_key=controls.feed).start()
    print(
        f"panopticon: capturing on {interface}"
        + (f" with BPF filter {args.filter!r}" if args.filter else "")
        + " — Ctrl+C or q to stop"
    )

    reported_worker_errors = 0
    drained = 0

    def run_loop():
        nonlocal reported_worker_errors
        while not shutdown.is_set() and not keyboard_stop.is_set():
            shutdown.wait(args.refresh)
            now = time.time()
            if keyboard_stop.is_set():
                break
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
            store.flush_velocity(now)
            store.prune(now)
            worker.prune(now)

    try:
        if args.no_ui:
            run_loop()
        else:
            # Drive the dashboard from Live's refresh thread, which reads
            # store snapshots only; the maintenance loop runs alongside it.
            ui_refresh_per_second = 1.0 / max(args.refresh, 1e-3)
            dashboard = build_dashboard(
                store,
                refresh_per_second=ui_refresh_per_second,
                controls=controls,
                capture_info={"interface": interface, "filter": args.filter},
            )
            with dashboard:
                run_loop()
    except KeyboardInterrupt:
        pass
    finally:
        shutdown.set()
        keyboard_stop.set()
        if keyboard is not None:
            keyboard.stop()
        sniffer.stop()
        sniffer.join(timeout=5)
        worker.stop()
        worker.join()
        drained = worker.drain()
        worker.flush()
        for exporter in exporters:
            try:
                exporter.close()
            except Exception as exc:  # noqa: BLE001 - contained, see #9
                print(
                    f"panopticon: could not close exporter {type(exporter).__name__}: {exc}",
                    file=sys.stderr,
                )
        try:
            alert_exporter.close()
        except Exception as exc:  # noqa: BLE001 - contained, see #9
            print(f"panopticon: could not close alert log {alert_path}: {exc}", file=sys.stderr)
        if args.tags_file:
            _save_tags(store, args.tags_file)

    store.flush_velocity(time.time())
    telemetry = store.snapshot_telemetry()
    print(
        f"panopticon: stopped — {telemetry['total_packets']} packets, "
        f"{telemetry['dropped_packets']} dropped, {drained} drained, "
        f"{telemetry['alerts_total']} alerts, "
        f"exports: {args.export_pcap}, {args.export_csv}, {alert_path}"
    )
    for alert in store.snapshot_alerts():
        print(f"  [{alert.severity}] {alert.kind}: {alert.summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
