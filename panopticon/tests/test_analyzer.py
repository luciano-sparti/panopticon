"""End-to-end tests of the ``analyzer.main`` CLI wiring (no live capture).

``main`` is exercised with a fake ``Sniffer`` and real pipeline/exporter
components writing into tmp paths, covering exit codes, graceful shutdown,
signal handling, and shutdown telemetry.
"""

import signal

from panopticon.analyzer import main
from panopticon.core.event import PacketEvent


class FakeAsyncSniffer:
    exception = None
    thread = None


class FakeSniffer:
    """Mirrors the ``Sniffer`` API; capture "fails" after a few loop checks."""

    def __init__(self, interface, packet_queue, store, bpf_filter=None):
        self._interface = interface
        self.packet_queue = packet_queue
        self.store = store
        self.bpf_filter = bpf_filter
        self._sniffer = FakeAsyncSniffer()
        self.iterations = 0
        self.fail_after = 2
        self.sig_on_start = False

    @property
    def interface(self):
        return self._interface

    @property
    def running(self):
        return self.iterations < self.fail_after

    @property
    def exception(self):
        return self._sniffer.exception

    @property
    def capture_failed(self):
        self.iterations += 1
        return self.iterations >= self.fail_after

    def start(self):
        if self.sig_on_start:
            signal.raise_signal(signal.SIGINT)
        self.packet_queue.put((
            b"\x00" * 60,
            PacketEvent(0.0, "10.0.0.1", "8.8.8.8", "tcp", 1000, 50000, 100, "ephemeral"),
        ))

    def stop(self):
        pass

    def join(self, timeout=None):
        pass


def make_args(tmp_path, extra=()):
    return [
        "-i", "eth0",
        "--export-pcap", str(tmp_path / "s.pcap"),
        "--export-csv", str(tmp_path / "s.csv"),
        "--refresh", "0.01",
    ] + list(extra)


def patch_healthy(monkeypatch):
    monkeypatch.setattr("panopticon.analyzer.preflight", lambda interface: "")
    monkeypatch.setattr("panopticon.analyzer.Sniffer", FakeSniffer)


def test_main_returns_2_without_interface(monkeypatch):
    monkeypatch.setattr("panopticon.analyzer.auto_detect_interface", lambda: "")
    assert main(["-i", ""]) == 2


def test_main_returns_2_when_preflight_fails(monkeypatch, tmp_path):
    monkeypatch.setattr("panopticon.analyzer.preflight", lambda interface: "no capture privileges")
    assert main(make_args(tmp_path)) == 2


def test_main_returns_2_when_exporter_path_unwritable(monkeypatch, tmp_path):
    patch_healthy(monkeypatch)
    args = make_args(tmp_path, ["--export-pcap", str(tmp_path)])  # a directory
    assert main(args) == 2


def test_main_graceful_shutdown_and_telemetry(monkeypatch, tmp_path, capsys):
    patch_healthy(monkeypatch)
    assert main(make_args(tmp_path)) == 0
    out, err = capsys.readouterr()
    assert "capturing on eth0" in out
    assert "stopped" in out
    assert "1 packets" in out
    assert "1 alerts" in out
    assert "[info] high_port" in out
    assert "capture stopped unexpectedly" in err


def test_main_signal_sets_shutdown_and_returns_zero(monkeypatch, tmp_path):
    patch_healthy(monkeypatch)

    class SigSniffer(FakeSniffer):
        def __init__(self, interface, packet_queue, store, bpf_filter=None):
            super().__init__(interface, packet_queue, store, bpf_filter)
            self.sig_on_start = True

    monkeypatch.setattr("panopticon.analyzer.Sniffer", SigSniffer)
    assert main(make_args(tmp_path)) == 0
