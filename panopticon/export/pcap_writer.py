"""Streaming PCAP exporter.

Wraps ``scapy.utils.PcapWriter`` in append mode and writes raw link-layer
frames. When no ``linktype`` is given it is inferred from the first frame
(Ethernet vs. raw IP) instead of being forced to Ethernet, so non-Ethernet
captures produce pcap files that parse correctly. Writes accumulate in the
writer's file buffer and are flushed to disk once ``flush_every`` frames or
``flush_bytes`` bytes have queued since the last flush, bounding I/O stalls
in the pipeline thread.
"""

from __future__ import annotations

from typing import Optional

from scapy.config import conf
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.utils import PcapWriter

from .base import BaseExporter

# Default batch thresholds for PCAP flushes.
DEFAULT_FLUSH_EVERY = 500
DEFAULT_FLUSH_BYTES = 1_000_000

# EtherTypes that identify a real Ethernet frame during link-type guessing.
_ETHER_TYPES = (0x0800, 0x0806, 0x8035, 0x8100, 0x86DD, 0x88A8, 0x88CC, 0x9000)


class PcapExportWriter(BaseExporter):
    """Append-mode ``PcapWriter`` sink for raw frames.

    ``linktype`` overrides auto-detection; when ``None`` the writer guesses
    from the first frame (falling back to Ethernet / ``DLT_EN10MB`` exactly
    like Scapy itself does for unparseable frames).
    """

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
        self._linktype = linktype
        self._writer = PcapWriter(path, append=True, linktype=linktype)
        self._header_ready = False
        self._count = 0
        self._bytes = 0

    def write(self, raw: bytes, event) -> None:
        if not self._header_ready:
            self._ensure_header(raw)
            self._header_ready = True
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

    # ------------------------------------------------------------------
    # Linktype inference
    # ------------------------------------------------------------------

    def _ensure_header(self, raw: bytes) -> None:
        """Write the pcap file header, inferring the linktype if needed."""
        linktype = self._linktype if self._linktype is not None else self._infer_linktype(raw)
        if linktype is None:
            self._writer.write_header(None)
        else:
            self._writer.linktype = linktype
            self._writer.write_header(None)

    @staticmethod
    def _infer_linktype(raw: bytes) -> Optional[int]:
        """Guess a DLT value from the first frame, or ``None`` if unknown."""
        if len(raw) >= 14:
            try:
                eth = Ether(raw)
                if eth.type in _ETHER_TYPES:
                    return conf.l2types.layer2num[Ether]
            except Exception:  # noqa: BLE001 - malformed frame
                pass
        if raw:
            nibble = raw[0] >> 4
            if nibble == 4:
                return conf.l2types.layer2num[IP]
            if nibble == 6:
                return conf.l2types.layer2num[IPv6]
        return None
