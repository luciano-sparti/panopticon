"""Detection framework: the detector interface and the engine manager.

``BaseDetector`` is the abstract interface every anomaly detector implements;
``DetectorEngine`` runs each detector synchronously per event, dedups /
cools down repeated alerts, and pushes accepted ``AlertEvent`` objects into
the shared ``StateStore``.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Dict, Hashable, List, Optional

from ..core.event import AlertEvent, PacketEvent
from ..core.store import StateStore

# Default cooldown (seconds) between accepted alerts of the same kind/source.
ALERT_COOLDOWN = 30.0


class BaseDetector(ABC):
    """Abstract anomaly detector.

    Subclasses implement ``process_event`` to inspect every captured
    ``PacketEvent`` (plus the raw frame when payload inspection is needed)
    and return an ``AlertEvent`` when suspicious traffic is found.

    ``engine_cooldown`` overrides the engine-wide dedup cooldown for this
    detector:

    - ``None`` (default): the engine dedups by ``(kind, src)`` using its
      own cooldown — e.g. per-source SYN-scan cooldown.
    - ``0.0``: the engine never dedups this detector; the detector is
      expected to track its own per-flow cooldown (see HighPortDetector).
    """

    engine_cooldown: Optional[float] = None

    @abstractmethod
    def process_event(
        self,
        event: PacketEvent,
        now: float,
        raw: Optional[bytes] = None,
    ) -> Optional[AlertEvent]:
        """Inspect one event; return an alert or ``None``."""

    def prune(self, now: float) -> int:
        """Drop stale internal state. Returns the number of entries removed."""
        return 0


class DetectorEngine:
    """Runs every registered detector per event and forwards alerts.

    The engine owns alert dedup/cooldown and persists accepted alerts to the
    ``StateStore`` so the UI and exporters can consume them later.
    """

    def __init__(
        self,
        store: StateStore,
        detectors: Optional[List[BaseDetector]] = None,
        cooldown: float = ALERT_COOLDOWN,
    ) -> None:
        self._store = store
        self._cooldown = cooldown
        self._detectors: List[BaseDetector] = list(detectors or [])
        # Dedup key -> last accepted alert timestamp.
        self._last_alert: Dict[Hashable, float] = {}

    def register(self, detector: BaseDetector) -> None:
        """Add a detector to run on every event."""
        self._detectors.append(detector)

    def detectors(self) -> List[BaseDetector]:
        """Snapshot of the registered detectors."""
        return list(self._detectors)

    def process_event(
        self,
        event: PacketEvent,
        now: Optional[float] = None,
        raw: Optional[bytes] = None,
    ) -> Optional[AlertEvent]:
        """Run every detector on one event; return the first accepted alert.

        Every accepted alert is pushed to the store. Uses ``event.timestamp``
        when ``now`` is omitted so detection stays deterministic on
        synthetic timestamps.
        """
        ts = event.timestamp if now is None else now
        first: Optional[AlertEvent] = None
        for detector in self._detectors:
            alert = detector.process_event(event, ts, raw)
            if alert is None:
                continue
            if not self._allow(alert, detector, ts):
                continue
            if self._store is not None:
                self._store.add_alert(alert)
            if first is None:
                first = alert
        return first

    def prune(self, now: Optional[float] = None) -> int:
        """Run housekeeping on every detector and the engine dedup map.

        Returns the total number of entries removed.
        """
        ts = time.time() if now is None else now
        total = 0
        for detector in self._detectors:
            total += detector.prune(ts)
        stale = [key for key, last in self._last_alert.items()
                 if ts - last > self._cooldown]
        for key in stale:
            del self._last_alert[key]
        return total + len(stale)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _allow(self, alert: AlertEvent, detector: BaseDetector, ts: float) -> bool:
        """Apply cooldown dedup for a detector, keyed by ``(kind, src)``."""
        cooldown = (
            self._cooldown
            if detector.engine_cooldown is None
            else detector.engine_cooldown
        )
        if cooldown <= 0:
            return True
        key: Hashable = (alert.kind, alert.src)
        last = self._last_alert.get(key)
        if last is not None and ts - last < cooldown:
            return False
        self._last_alert[key] = ts
        return True
