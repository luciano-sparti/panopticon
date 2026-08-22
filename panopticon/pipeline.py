"""Unified background pipeline worker.

Drains a ``queue.Queue`` of ``(raw_bytes, PacketEvent)`` tuples produced by
the capture thread, updates the shared ``StateStore``, runs detection
synchronously through a ``DetectorEngine`` (which forwards accepted
``AlertEvent`` objects to the store), and feeds every event to the
configured exporters.

The worker runs on a daemon thread so the CLI never blocks on capture I/O;
``stop`` + ``drain`` provide a graceful shutdown path that processes the
tail of the queue and flushes exporters before the process exits.
"""

from __future__ import annotations

import queue
import threading
from typing import Iterable, Optional

from .core.event import PacketEvent
from .core.store import StateStore
from .detection.base import DetectorEngine

# How long the worker blocks on ``get`` when the queue is idle (seconds).
POLL_INTERVAL = 0.2


class PipelineWorker(threading.Thread):
    """Background consumer for captured packets.

    Wires capture -> store -> detect -> export. Uses the normal ``Thread``
    lifecycle (``start`` / ``join``); ``stop`` + ``drain`` + ``flush``
    implement graceful shutdown.

    Exporter/detector errors are contained: the offending packet is skipped
    and the error is recorded via :attr:`error_count` / :attr:`last_error`
    instead of killing the worker thread.
    """

    def __init__(
        self,
        packet_queue: queue.Queue,
        store: StateStore,
        exporters: Iterable = (),
        detector: Optional[DetectorEngine] = None,
        poll_interval: float = POLL_INTERVAL,
        alert_exporter=None,
    ) -> None:
        super().__init__(name="panopticon-pipeline", daemon=True)
        self._queue = packet_queue
        self._store = store
        self._exporters = tuple(exporters)
        self._detector = detector if detector is not None else DetectorEngine(store)
        self._poll_interval = poll_interval
        self._alert_exporter = alert_exporter
        self._stop = threading.Event()
        self._error_count = 0
        self._last_error: Optional[str] = None
        self._error_lock = threading.Lock()

    @property
    def error_count(self) -> int:
        """Number of packets skipped because of exporter/detector errors."""
        with self._error_lock:
            return self._error_count

    @property
    def last_error(self) -> Optional[str]:
        """Human-readable description of the most recent processing error."""
        with self._error_lock:
            return self._last_error

    def _record_error(self, exc: BaseException) -> None:
        with self._error_lock:
            self._error_count += 1
            self._last_error = f"{type(exc).__name__}: {exc}"

    # ------------------------------------------------------------------
    # Lifecycle (graceful shutdown)
    # ------------------------------------------------------------------

    def stop(self) -> None:
        """Ask the worker to exit after the next queue poll."""
        self._stop.set()

    def drain(self) -> int:
        """Process everything left in the queue (called at shutdown).

        Returns the number of items processed.
        """
        count = 0
        while True:
            try:
                raw, event = self._queue.get_nowait()
            except queue.Empty:
                break
            try:
                self._process(raw, event)
            except Exception as exc:  # noqa: BLE001 - contained, see #9
                self._record_error(exc)
            count += 1
        return count

    def flush(self) -> None:
        """Push buffered exporter data to disk."""
        for exporter in self._exporters:
            exporter.flush()
        if self._alert_exporter is not None:
            self._alert_exporter.flush()

    def prune(self, now: Optional[float] = None) -> int:
        """Run detector housekeeping (expiry / dedup-map cleanup)."""
        return self._detector.prune(now)

    # ------------------------------------------------------------------
    # Thread body
    # ------------------------------------------------------------------

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                raw, event = self._queue.get(timeout=self._poll_interval)
            except queue.Empty:
                continue
            try:
                self._process(raw, event)
            except Exception as exc:  # noqa: BLE001 - contained, see #9
                self._record_error(exc)

    def _process(self, raw: bytes, event: PacketEvent) -> None:
        """Record, detect, and export a single packet."""
        self._store.update(event)
        alert = self._detector.process_event(event, None, raw)
        if alert is not None and self._alert_exporter is not None:
            try:
                self._alert_exporter.write_alert(alert)
            except Exception as exc:  # noqa: BLE001 - contained, see #9
                self._record_error(exc)
        for exporter in self._exporters:
            exporter.write(raw, event)
