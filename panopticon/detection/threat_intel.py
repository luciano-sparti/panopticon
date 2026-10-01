"""Threat Intelligence anomaly detector.

Detects network communication with known malicious IPs, command & control (C2)
infrastructure, Tor exit nodes, and botnet relays using cached threat feeds.
"""

from __future__ import annotations

from ..core.enrichment import GeoEnricher, get_default_enricher
from ..core.event import AlertEvent, PacketEvent
from .base import BaseDetector


class ThreatIntelDetector(BaseDetector):
    """Flags packets communicating with known malicious IPs / threat feeds."""

    def __init__(self, enricher: GeoEnricher | None = None) -> None:
        self._enricher = enricher or get_default_enricher()

    def process_event(
        self,
        event: PacketEvent,
        now: float,
        raw: bytes | None = None,
    ) -> AlertEvent | None:
        # Check source IP
        threat = self._enricher.lookup_threat(event.src)
        matched_ip = event.src
        if threat is None:
            # Check destination IP
            threat = self._enricher.lookup_threat(event.dst)
            matched_ip = event.dst

        if threat is not None and threat.is_threat:
            return AlertEvent(
                time=now,
                severity="critical",
                kind="threat_intel",
                summary=(
                    f"Threat intelligence alert: {matched_ip} identified as "
                    f"{threat.threat_type} ({threat.source} — {threat.description})"
                ),
                src=event.src,
                dst=event.dst,
            )
        return None
