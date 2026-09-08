"""Streaming alert exporter.

Writes one JSON object per accepted ``AlertEvent`` to ``path`` in
append-only JSONL form. The file is opened in append mode so consecutive
runs keep one alert log. Flush cadence defaults to every 10 alerts.
"""

from __future__ import annotations

import json

DEFAULT_FLUSH_EVERY = 10


class AlertExportWriter:
    """Append-mode JSONL sink for detector alerts."""

    def __init__(self, path: str, flush_every: int = DEFAULT_FLUSH_EVERY) -> None:
        self._path = path
        self._flush_every = flush_every
        # JSONL has no header; the file is opened in append mode so
        # consecutive runs keep one alert log.
        self._fh = open(path, "a", encoding="utf-8")  # noqa: SIM115 - persistent stream handle
        self._count = 0

    def write_alert(self, alert) -> None:
        self._fh.write(
            json.dumps(
                {
                    "time": alert.time,
                    "severity": alert.severity,
                    "kind": alert.kind,
                    "summary": alert.summary,
                    "src": alert.src,
                    "dst": alert.dst,
                }
            )
            + "\n"
        )
        self._count += 1
        if self._count >= self._flush_every:
            self.flush()

    def flush(self) -> None:
        self._fh.flush()
        self._count = 0

    def close(self) -> None:
        self.flush()
        self._fh.close()
