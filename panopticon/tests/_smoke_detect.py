"""Smoke harness: drive the detector engine with synthetic events.

Run via:  python -m panopticon.tests._smoke_detect
No root required. Builds PacketEvents (incl. TCP flags) and runs them through
the real DetectorEngine + StateStore, then asserts the expected alerts fired.
"""
from __future__ import annotations

import time

from panopticon.core.event import PacketEvent, AlertEvent
from panopticon.core.store import StateStore
from panopticon.detection.base import DetectorEngine
from panopticon.detection.syn_scan import SynScanDetector
from panopticon.detection.plaintext import PlaintextDetector
from panopticon.detection.high_port import HighPortDetector


def _ev(src, dst, dport, proto="tcp", flags="S", size=64, service="", now=None):
    return PacketEvent(
        timestamp=now if now is not None else time.time(),
        src=src, dst=dst, proto=proto,
        sport=1000, dport=dport, size=size, service=service, flags=flags,
    )


def main() -> None:
    store = StateStore()
    engine = DetectorEngine(
        store=store,
        detectors=[
            SynScanDetector(threshold=20, window=5.0),
            PlaintextDetector(),
            HighPortDetector(threshold_port=49152),
        ],
        cooldown=30.0,
    )

    # SYN scan: 25 distinct targets from one source -> one SYN_SCAN alert
    now = time.time()
    for i in range(25):
        engine.process_event(_ev("192.168.1.10", f"10.0.0.{i % 254 + 1}", 80,
                                 flags="S", now=now), now=now)

    # plaintext: HTTP GET payload (port 80, PA flags)
    engine.process_event(_ev("10.0.0.9", "10.0.0.8", 80, flags="PA",
                             service="http", now=now), now=now)

    # high port
    engine.process_event(_ev("10.0.0.7", "10.0.0.6", 50000, now=now), now=now)

    alerts = store.snapshot_alerts()
    kinds = {a.kind for a in alerts}
    assert "syn_scan" in kinds, f"expected syn_scan alert, got {kinds}"
    assert "plaintext" in kinds, f"expected plaintext alert, got {kinds}"
    assert "high_port" in kinds, f"expected high_port alert, got {kinds}"
    print(f"detect smoke OK: alerts fired = {sorted(kinds)}")


if __name__ == "__main__":
    main()
