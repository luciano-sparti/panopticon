"""Unified background pipeline worker.

Drains a ``queue.Queue`` of ``(raw_bytes, PacketEvent)`` tuples produced by
the capture thread, updates the shared ``StateStore``, runs detection
synchronously (a no-op ``DetectorEngine`` hook until Phase 3 plugs in real
heuristics), and feeds every event to the configured exporters.

The worker runs on a daemon thread so the CLI never blocks on capture I/O;
``stop`` + ``drain`` provide a graceful shutdown path that processes the
tail of the queue and flushes exporters before the process exits.
"""

from __future__ import annotations

import queue
import threading
from typing import Iterable, Optional

from .core.event import AlertEvent, PacketEvent
from .core.store import StateStore

# How long the worker blocks on ``get`` when the queue is idle (seconds).
POLL_INTERVAL = 0.2


class DetectorEngine:
    """Detection hook consumed by the pipeline (Phase 3 plugs in here).

    Subclasses implement ``analyze`` and return an ``AlertEvent`` when
    traffic looks suspicious; the pipeline calls it once per event.
    """

    def analyze(self, event: PacketEvent) -> Optional[AlertEvent]:
        return None


class NoopDetector(DetectorEngine):
    """Placeholder detector: accepts everything, raises nothing."""

    def analyze(self, event: PacketEvent) -> Optional[AlertEvent]:
        return None


class PipelineWorker(threading.Thread):
    """Background consumer for captured packets.

    Wires capture -> store -> detect -> export. Uses the normal ``Thread``
    lifecycle (``start`` / ``join``); ``stop`` + ``drain`` + ``flush``
    implement graceful shutdown.
    """

    def __init__(
        self,
        packet_queue: queue.Queue,
        store: StateStore,
        exporters: Iterable = (),
        detector: Optional[DetectorEngine] = None,
        poll_interval: float = POLL_INTERVAL,
    ) -> None:
        super().__init__(name="panopticon-pipeline", daemon=True)
        self._queue = packet_queue
        self._store = store
        self._exporters = tuple(exporters)
        self._detector = detector if detector is not None else NoopDetector()
        self._poll_interval = poll_interval
        self._stop = threading.Event()

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
            self._process(raw, event)
            count += 1
        return count

    def flush(self) -> None:
        """Push buffered exporter data to disk."""
        for exporter in self._exporters:
            exporter.flush()

    # ------------------------------------------------------------------
    # Thread body
    # ------------------------------------------------------------------

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                raw, event = self._queue.get(timeout=self._poll_interval)
            except queue.Empty:
                continue
            self._process(raw, event)

    def _process(self, raw: bytes, event: PacketEvent) -> None:
        """Record, detect, and export a single packet."""
        self._store.update(event)
        self._detector.analyze(event)
        for exporter in self._exporters:
            exporter.write(raw, event)
