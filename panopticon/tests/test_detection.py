"""DetectorEngine manager tests (dedup, store wiring, housekeeping)."""

import pytest

from panopticon.core.event import AlertEvent
from panopticon.core.store import ALERTS_MAXLEN, StateStore
from panopticon.detection.base import BaseDetector, DetectorEngine


class FixedDetector(BaseDetector):
    """Returns a fixed alert for every event; counts calls."""

    def __init__(self, alert, engine_cooldown=None):
        self._alert = alert
        self.calls = 0
        self.engine_cooldown = engine_cooldown
        self.pruned_at = []

    def process_event(self, event, now, raw=None):
        self.calls += 1
        return self._alert

    def prune(self, now):
        self.pruned_at.append(now)
        return 2


def alert(t, src="10.0.0.1"):
    return AlertEvent(time=t, severity="warn", kind="fixed",
                      summary="synthetic", src=src, dst="8.8.8.8")


def test_engine_runs_all_detectors():
    a, b = FixedDetector(alert(0.0)), FixedDetector(alert(0.0))
    engine = DetectorEngine(StateStore(), detectors=[a, b])
    assert engine.process_event(object(), 1.0) is not None
    assert a.calls == 1 and b.calls == 1


def test_engine_registers_detectors():
    engine = DetectorEngine(StateStore())
    assert engine.detectors() == []
    engine.register(FixedDetector(alert(0.0)))
    assert len(engine.detectors()) == 1


def test_engine_pushes_alerts_into_store():
    store = StateStore()
    engine = DetectorEngine(store, detectors=[FixedDetector(alert(0.0))])
    assert engine.process_event(object(), 1.0) is not None
    alerts = store.snapshot_alerts()
    assert len(alerts) == 1
    assert alerts[0].kind == "fixed"
    assert store.snapshot_telemetry()["alerts_total"] == 1


def test_engine_dedup_keyed_by_kind_and_src():
    store = StateStore()
    engine = DetectorEngine(
        store,
        detectors=[FixedDetector(alert(0.0))],
        cooldown=30.0,
    )
    assert engine.process_event(object(), 1.0) is not None
    # Same kind + src within cooldown: suppressed.
    assert engine.process_event(object(), 2.0) is None
    assert len(store.snapshot_alerts()) == 1
    # Same kind, different src: allowed.
    engine.register(FixedDetector(alert(0.0, src="10.0.0.2")))
    assert engine.process_event(object(), 3.0) is not None
    assert len(store.snapshot_alerts()) == 2


def test_engine_cooldown_zero_disables_dedup():
    store = StateStore()
    engine = DetectorEngine(
        store,
        detectors=[FixedDetector(alert(0.0), engine_cooldown=0.0)],
        cooldown=30.0,
    )
    assert engine.process_event(object(), 1.0) is not None
    assert engine.process_event(object(), 2.0) is not None
    assert len(store.snapshot_alerts()) == 2


def test_engine_uses_event_timestamp_when_now_missing():
    store = StateStore()
    engine = DetectorEngine(
        store,
        detectors=[FixedDetector(alert(0.0))],
        cooldown=30.0,
    )
    from panopticon.core.event import PacketEvent

    event = PacketEvent(5.0, "a", "b", "tcp", 1, 80, 100, "http")
    assert engine.process_event(event) is not None


def test_engine_prune_delegates_to_detectors():
    detector = FixedDetector(alert(0.0))
    engine = DetectorEngine(StateStore(), detectors=[detector])
    assert engine.prune(now=100.0) == 2
    assert detector.pruned_at == [100.0]


def test_alert_buffer_is_bounded_and_counter_keeps_running():
    store = StateStore()
    for i in range(ALERTS_MAXLEN + 10):
        store.add_alert(alert(float(i)))
    assert len(store.snapshot_alerts()) == ALERTS_MAXLEN
    assert store.snapshot_telemetry()["alerts_total"] == ALERTS_MAXLEN + 10
