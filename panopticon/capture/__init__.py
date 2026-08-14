"""Live packet capture support (preflight + async sniffer)."""

from .sniffer import (
    CAP_NET_RAW,
    Sniffer,
    auto_detect_interface,
    handle_packet,
    preflight,
)

__all__ = [
    "CAP_NET_RAW",
    "Sniffer",
    "auto_detect_interface",
    "handle_packet",
    "preflight",
]
