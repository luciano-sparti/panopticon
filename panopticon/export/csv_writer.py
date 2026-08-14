"""Streaming CSV flow-log exporter.

Writes one row per packet event (the full session, not a UI-side snapshot)
as a ``csv.DictWriter`` and flushes periodically so recent flows land on
disk even before shutdown.

The file is opened in append mode (matching the PCAP exporter); the header
row is only written when the file is new or empty so consecutive runs keep
one header. Flush cadence defaults to every 100 rows.
"""

from __future__ import annotations

import csv
import os
from typing import Dict, List

from .base import BaseExporter

# Column order for the flow log.
CSV_FIELDNAMES: List[str] = [
    "ts",
    "src",
    "dst",
    "proto",
    "sport",
    "dport",
    "service",
    "size",
]

# Default row count between flushes.
DEFAULT_FLUSH_EVERY = 100


class CsvExportWriter(BaseExporter):
    """Append-mode row stream to ``path`` with periodic flushes."""

    def __init__(self, path: str, flush_every: int = DEFAULT_FLUSH_EVERY) -> None:
        self._path = path
        self._flush_every = flush_every
        is_new = not os.path.exists(path) or os.path.getsize(path) == 0
        self._fh = open(path, "a", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(self._fh, fieldnames=CSV_FIELDNAMES)
        if is_new:
            self._writer.writeheader()
        self._count = 0

    def write(self, raw: bytes, event) -> None:
        self._writer.writerow(self._row(event))
        self._count += 1
        if self._count >= self._flush_every:
            self.flush()

    def _row(self, event) -> Dict[str, object]:
        return {
            "ts": event.timestamp,
            "src": event.src,
            "dst": event.dst,
            "proto": event.proto,
            "sport": event.sport,
            "dport": event.dport,
            "service": event.service,
            "size": event.size,
        }

    def flush(self) -> None:
        self._fh.flush()
        self._count = 0

    def close(self) -> None:
        self.flush()
        self._fh.close()
