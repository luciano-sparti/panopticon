"""Live packet capture support (preflight + async sniffer)."""

from .presets import (
    BPF_PRESETS,
    get_preset,
    match_preset_event,
    resolve_preset_filter,
)
from .sniffer import (
    CAP_NET_RAW,
    Sniffer,
    auto_detect_interface,
    handle_packet,
    preflight,
    validate_bpf_filter,
)

__all__ = [
    "BPF_PRESETS",
    "CAP_NET_RAW",
    "Sniffer",
    "auto_detect_interface",
    "get_preset",
    "handle_packet",
    "match_preset_event",
    "preflight",
    "resolve_preset_filter",
    "validate_bpf_filter",
]
