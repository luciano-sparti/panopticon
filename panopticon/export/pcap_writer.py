"""Streaming PCAP exporter.

Wraps ``scapy.utils.PcapWriter`` in append mode and writes raw link-layer
frames. Writes accumulate in the writer's file buffer and are flushed to
disk once ``flush_every`` frames or ``flush_bytes`` bytes have queued since
the last flush, bounding I/O stalls in the pipeline thread.
"""

from __future__ import annotations

from typing import Optional

from scapy.utils import DLT_EN10MB, PcapWriter

from .base import BaseExporter

# Default batch thresholds for PCAP flushes.
DEFAULT_FLUSH_EVERY = 500
DEFAULT_FLUSH_BYTES = 1_000_000


class PcapExportWriter(BaseExporter):
    """Append-mode ``PcapWriter`` sink for raw frames."""

    def __init__(
        self,
        path: str,
        flush_every: int = DEFAULT_FLUSH_EVERY,
        flush_bytes: int = DEFAULT_FLUSH_BYTES,
        linktype: Optional[int] = None,
    ) -> None:
        self._path = path
        self._flush_every = flush_every
        self._flush_bytes = flush_bytes
        self._writer = PcapWriter(path, append=True, linktype=linktype or DLT_EN10MB)
        self._count = 0
        self._bytes = 0

    def write(self, raw: bytes, event) -> None:
        self._writer.write(raw)
        self._count += 1
        self._bytes += len(raw)
        if self._count >= self._flush_every or self._bytes >= self._flush_bytes:
            self.flush()

    def flush(self) -> None:
        self._writer.flush()
        self._count = 0
        self._bytes = 0

    def close(self) -> None:
        self.flush()
        self._writer.close()
