"""Common exporter interface consumed by the pipeline worker."""

from abc import ABC, abstractmethod


class BaseExporter(ABC):
    """Streaming sink written to by the pipeline.

    ``write`` receives the raw captured frame plus its parsed ``PacketEvent``.
    Implementations buffer writes and expose ``flush`` so the pipeline can
    bound I/O stalls; ``close`` releases the underlying file handle.
    """

    @abstractmethod
    def write(self, raw: bytes, event) -> None:
        """Persist one frame / flow record."""

    @abstractmethod
    def flush(self) -> None:
        """Push buffered data to disk."""

    @abstractmethod
    def close(self) -> None:
        """Flush and release the underlying file handle."""
