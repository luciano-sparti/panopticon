"""End-to-end tests of the ``analyzer.main`` CLI wiring (no live capture).

``main`` is exercised with a fake ``Sniffer`` and real pipeline/exporter
components writing into tmp paths, covering exit codes, graceful shutdown,
signal handling, and shutdown telemetry.
"""

import json
import signal

from panopticon.analyzer import _load_tags, _save_tags, build_parser, main
from panopticon.core.event import PacketEvent
from panopticon.core.store import StateStore


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


def test_version_flag_prints_version_and_exits_zero(capsys):
    try:
        main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    out, _ = capsys.readouterr()
    assert "panopticon 0.5.0" in out


def test_new_flags_parse():
    parser = build_parser()
    args = parser.parse_args(["--enable-kill", "--tags-file", "/tmp/t.json"])
    assert args.enable_kill is True
    assert args.tags_file == "/tmp/t.json"
    defaults = parser.parse_args([])
    assert defaults.enable_kill is False
    assert defaults.tags_file == ""


def test_tags_file_roundtrip_load_and_save(tmp_path):
    path = tmp_path / "tags.json"
    path.write_text('{"1.1.1.1": ["web", "web"], "2.2.2.2": ["x"]}',
                    encoding="utf-8")
    store = StateStore()
    _load_tags(store, str(path))
    assert store.tags_for("1.1.1.1") == {"web"}
    assert store.tags_for("2.2.2.2") == {"x"}

    store.add_tag("3.3.3.3", "extra")
    _save_tags(store, str(path))
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["1.1.1.1"] == ["web"]
    assert data["3.3.3.3"] == ["extra"]


def test_tags_file_ignores_bad_load(tmp_path):
    path = tmp_path / "tags.json"
    path.write_text("not json {", encoding="utf-8")
    store = StateStore()
    _load_tags(store, str(path))  # must not raise
    assert store.snapshot_tags() == {}


def test_main_writes_tags_file_on_exit(monkeypatch, tmp_path):
    patch_healthy(monkeypatch)
    tags = tmp_path / "tags.json"
    assert main(make_args(tmp_path, ["--tags-file", str(tags)])) == 0
    assert isinstance(json.loads(tags.read_text(encoding="utf-8")), dict)


def test_main_no_ui_headless_path(monkeypatch, tmp_path, capsys):
    patch_healthy(monkeypatch)
    assert main(make_args(tmp_path, ["--no-ui"])) == 0
    out, err = capsys.readouterr()
    assert "capturing on eth0" in out
    assert "1 packets" in out
