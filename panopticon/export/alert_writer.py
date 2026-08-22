"""Streaming alert exporter.

Writes one JSON object per accepted ``AlertEvent`` to ``path`` in
append-only JSONL form. The file is opened in append mode so consecutive
runs keep one alert log. Flush cadence defaults to every 10 alerts.
"""

from __future__ import annotations

import json
import os
from typing import Optional

from .base import BaseExporter

DEFAULT_FLUSH_EVERY = 10


class AlertExportWriter:
    """Append-mode JSONL sink for detector alerts."""

    def __init__(self, path: str, flush_every: int = DEFAULT_FLUSH_EVERY) -> None:
        self._path = path
        self._flush_every = flush_every
        is_new = not os.path.exists(path) or os.path.getsize(path) == 0
        self._fh = open(path, "a", encoding="utf-8")
        self._count = 0
        if is_new:
            # JSONL has no header; keep file creation explicit for tools.
            pass

    def write_alert(self, alert) -> None:
        self._fh.write(json.dumps({
            "time": alert.time,
            "severity": alert.severity,
            "kind": alert.kind,
            "summary": alert.summary,
            "src": alert.src,
            "dst": alert.dst,
        }) + "\n")
        self._count += 1
        if self._count >= self._flush_every:
            self.flush()

    def flush(self) -> None:
        self._fh.flush()
        self._count = 0

    def close(self) -> None:
        self.flush()
        self._fh.close()
