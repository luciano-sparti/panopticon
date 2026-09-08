"""DetectorEngine manager tests (dedup, store wiring, housekeeping)."""

from panopticon.core.clock import Clock
from panopticon.core.event import AlertEvent, PacketEvent
from panopticon.core.store import ALERTS_MAXLEN, StateStore
from panopticon.detection.bandwidth import BandwidthDetector
from panopticon.detection.base import BaseDetector, DetectorEngine
from panopticon.detection.beacon import BeaconDetector
from panopticon.detection.port_knock import PortKnockDetector
from panopticon.detection.scan_probe import ScanProbeDetector


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
    return AlertEvent(
        time=t, severity="warn", kind="fixed", summary="synthetic", src=src, dst="8.8.8.8"
    )


def test_engine_runs_all_detectors():
    a, b = FixedDetector(alert(0.0)), FixedDetector(alert(0.0))
    engine = DetectorEngine(StateStore(), detectors=[a, b])
    assert engine.process_event(object(), 1.0) != []
    assert a.calls == 1 and b.calls == 1


def test_engine_registers_detectors():
    engine = DetectorEngine(StateStore())
    assert engine.detectors() == []
    engine.register(FixedDetector(alert(0.0)))
    assert len(engine.detectors()) == 1


def test_engine_returns_all_alerts_per_event():
    a = FixedDetector(alert(0.0))
    b = FixedDetector(
        AlertEvent(
            time=0.0,
            severity="critical",
            kind="other",
            summary="synthetic",
            src="10.0.0.1",
            dst="8.8.8.8",
        )
    )
    engine = DetectorEngine(StateStore(), detectors=[a, b])
    alerts = engine.process_event(object(), 1.0)
    assert len(alerts) == 2
    assert {al.kind for al in alerts} == {"fixed", "other"}


def test_engine_pushes_alerts_into_store():
    store = StateStore()
    engine = DetectorEngine(store, detectors=[FixedDetector(alert(0.0))])
    assert engine.process_event(object(), 1.0) != []
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
    assert engine.process_event(object(), 1.0) != []
    # Same kind + src within cooldown: suppressed.
    assert engine.process_event(object(), 2.0) == []
    assert len(store.snapshot_alerts()) == 1
    # Same kind, different src: allowed.
    engine.register(FixedDetector(alert(0.0, src="10.0.0.2")))
    assert engine.process_event(object(), 3.0) != []
    assert len(store.snapshot_alerts()) == 2


def test_engine_cooldown_zero_disables_dedup():
    store = StateStore()
    engine = DetectorEngine(
        store,
        detectors=[FixedDetector(alert(0.0), engine_cooldown=0.0)],
        cooldown=30.0,
    )
    assert engine.process_event(object(), 1.0) != []
    assert engine.process_event(object(), 2.0) != []
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
    assert engine.process_event(event) != []


def test_engine_prune_delegates_to_detectors():
    detector = FixedDetector(alert(0.0))
    engine = DetectorEngine(StateStore(), detectors=[detector])
    assert engine.prune(now=100.0) == 2
    assert detector.pruned_at == [100.0]


def test_engine_prune_defaults_to_injected_clock():
    class _FakeMonotonic:
        def __init__(self, value):
            self.value = value

        def __call__(self):
            return self.value

    detector = FixedDetector(alert(0.0))
    engine = DetectorEngine(
        StateStore(),
        detectors=[detector],
        clock=Clock(_FakeMonotonic(42.0)),
    )
    # No explicit "now": the engine must read its (monotonic) clock so a
    # wall-clock step cannot wipe the dedup map.
    assert engine.prune() == 2
    assert detector.pruned_at == [42.0]


def test_alert_buffer_is_bounded_and_counter_keeps_running():
    store = StateStore()
    for i in range(ALERTS_MAXLEN + 10):
        store.add_alert(alert(float(i)))
    assert len(store.snapshot_alerts()) == ALERTS_MAXLEN
    assert store.snapshot_telemetry()["alerts_total"] == ALERTS_MAXLEN + 10


def _ev(ts, src="10.0.0.1", dst="8.8.8.8", dport=80, flags="S", size=60, proto="tcp"):
    return PacketEvent(ts, src, dst, proto, 40000, dport, size, "", flags=flags)


def test_phase9_detectors_run_together_through_engine():
    store = StateStore()
    engine = DetectorEngine(
        store,
        detectors=[
            BeaconDetector(min_conns=3),
            BandwidthDetector(window=10.0, threshold=2000),
            PortKnockDetector(threshold=3, window=10.0),
            ScanProbeDetector(threshold=3),
        ],
    )
    # Beacon: three regular 10s connections -> beaconing alert lands in store.
    for i in range(3):
        engine.process_event(_ev(10.0 * (i + 1)), 10.0 * (i + 1))
    # Port knock sweep: 4 distinct ports on one host.
    for _, port in enumerate((80, 443, 22, 8080)):
        engine.process_event(_ev(1.0, dport=port), 1.0)
    # Bandwidth burst: 2750 bytes from a dedicated source over a full 10s window.
    for i in range(12):
        engine.process_event(_ev(1.0 + i, src="10.0.0.9", size=250), 1.0 + i)
    # Probe scan: four NULL probes.
    for i in range(4):
        engine.process_event(_ev(2.0, dport=3000 + i, flags=""), 2.0)

    kinds = {a.kind for a in store.snapshot_alerts()}
    assert {"beaconing", "port_knock", "bandwidth", "null_scan"} <= kinds
