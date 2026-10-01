"""BPF capture filter presets for Panopticon.

Provides predefined BPF filter profiles for high-level monitoring, such as
Web traffic, DNS inspection, non-LAN external traffic, and suspicious high ports,
as well as fast packet-event matching for dynamic TUI stream filtering without
restarting capture.
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from panopticon.core.event import PacketEvent

BPF_PRESETS: dict[str, dict[str, str]] = {
    "all": {
        "name": "All Traffic",
        "filter": "",
        "description": "Capture all packets without BPF filtering",
    },
    "web": {
        "name": "Web Only",
        "filter": "tcp port 80 or tcp port 443",
        "description": "HTTP (80) and HTTPS (443) web traffic",
    },
    "dns": {
        "name": "DNS Traffic",
        "filter": "udp port 53 or tcp port 53",
        "description": "Standard UDP/TCP DNS queries and responses",
    },
    "non-lan": {
        "name": "Non-LAN Exfiltration",
        "filter": (
            "not (net 10.0.0.0/8 or net 172.16.0.0/12 or net 192.168.0.0/16 or net 127.0.0.0/8)"
        ),
        "description": "External / WAN traffic excluding RFC 1918 and loopback",
    },
    "suspicious-ports": {
        "name": "Suspicious High Ports",
        "filter": "tcp portrange 1024-65535 and not (port 8080 or port 8443)",
        "description": "High non-standard TCP ports (excluding common alternates 8080/8443)",
    },
}

_RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
)


def get_preset(key: str) -> dict[str, str] | None:
    """Return preset metadata for ``key``, or ``None`` if unknown."""
    return BPF_PRESETS.get(key.lower().strip())


def resolve_preset_filter(preset_name: str) -> str:
    """Return the raw BPF string for a preset key, or raise ``ValueError``."""
    key = preset_name.lower().strip()
    if key not in BPF_PRESETS:
        options = ", ".join(repr(k) for k in BPF_PRESETS)
        raise ValueError(f"unknown BPF preset {preset_name!r}; valid choices: {options}")
    return BPF_PRESETS[key]["filter"]


def match_preset_event(event: PacketEvent, preset_key: str) -> bool:
    """Return True if ``event`` satisfies the given preset filter criteria.

    Used by the TUI to filter live stream displays instantaneously without
    having to restart the underlying capture socket.
    """
    key = preset_key.lower().strip()
    if key in ("all", ""):
        return True

    if key == "web":
        return event.proto == "tcp" and (event.sport in (80, 443) or event.dport in (80, 443))

    if key == "dns":
        return event.proto in ("udp", "tcp") and (event.sport == 53 or event.dport == 53)

    if key == "non-lan":
        # Returns True if either src or dst is non-LAN / external
        for ip_str in (event.src, event.dst):
            if not ip_str:
                continue
            try:
                addr = ipaddress.ip_address(ip_str)
                if not any(addr in net for net in _RFC1918_NETWORKS) and not addr.is_loopback:
                    return True
            except ValueError:
                continue
        return False

    if key == "suspicious-ports":
        if event.proto != "tcp":
            return False
        return 1024 <= event.dport <= 65535 and event.dport not in (8080, 8443)

    return True
