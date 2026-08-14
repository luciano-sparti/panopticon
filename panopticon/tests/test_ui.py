"""Phase 4 UI tests: snapshot -> Rich renderables, keyboard watcher, dashboard.

Every test runs without a TTY, exercising the "no-root safety" path: the
dashboard, renderers, and keyboard watcher must degrade gracefully, never
raise, and never block on ``input()``.
"""

import io
import os
import threading
import time

from rich.console import Console
from rich.layout import Layout
from rich.table import Table

from panopticon.analyzer import build_parser
from panopticon.core.event import AlertEvent, PacketEvent
from panopticon.core.store import StateStore
from panopticon.ui import (
    KeyboardWatcher,
    build_dashboard,
    build_layout,
    render_alerts,
    render_stream_table,
    render_telemetry,
    render_top_talkers,
)
from panopticon.ui.tables import SEVERITY_STYLES


def ev(ts, src="10.0.0.1", dst="8.8.8.8", proto="tcp",
       sport=1000, dport=80, size=100, service="http"):
    return PacketEvent(ts, src, dst, proto, sport, dport, size, service)


def populated_store():
    store = StateStore()
    for i in range(5):
        store.update(ev(float(i), src=f"10.0.0.{i + 1}", size=100 + i * 10))
    store.add_alert(AlertEvent(1.0, "warn", "syn_scan",
                               "SYN scan detected", "10.0.0.1", "8.8.8.8"))
    store.add_alert(AlertEvent(2.0, "critical", "plaintext",
                               "Credential leak", "10.0.0.2", "8.8.8.8"))
    return store


def render_text(renderable, width=120):
    buf = io.StringIO()
    Console(width=width, file=buf).print(renderable)
    return buf.getvalue()


# ----------------------------------------------------------------------
# Tables (renderers produce Rich renderables from snapshots)
# ----------------------------------------------------------------------


def test_render_stream_table_from_snapshot():
    table = render_stream_table(populated_store().snapshot_stream())
    assert isinstance(table, Table)
    assert table.row_count == 5
    text = render_text(table)
    assert "10.0.0.5" in text and "http" in text


def test_render_stream_table_empty_is_safe():
    assert isinstance(render_stream_table([]), Table)


def test_render_top_talkers_from_snapshot():
    table = render_top_talkers(populated_store().snapshot_talkers())
    assert isinstance(table, Table)
    assert table.row_count == 5


def test_top_talkers_sorted_by_bytes_descending_with_bars():
    store = StateStore()
    for i in range(3):
        store.update(ev(0.0, src=f"ip{i}", size=100 * (i + 1)))
    table = render_top_talkers(store.snapshot_talkers())
    text = render_text(table)
    # Biggest talker first, and the activity bar uses block characters.
    assert text.index("ip2") < text.index("ip0")
    assert any(ch in text for ch in "▁▂▃▄▅▆▇█")


def test_top_talkers_empty_is_safe():
    table = render_top_talkers({})
    assert isinstance(table, Table)


def test_render_telemetry_from_snapshot():
    telemetry = populated_store().snapshot_telemetry()
    table = render_telemetry(telemetry)
    assert isinstance(table, Table)
    assert table.row_count == 9
    text = render_text(table)
    assert "Alerts" in text and "5" in text


def test_render_alerts_from_snapshot():
    table = render_alerts(populated_store().snapshot_alerts())
    assert isinstance(table, Table)
    assert table.row_count == 2
    text = render_text(table)
    assert "syn_scan" in text and "plaintext" in text


def test_render_alerts_empty_is_safe():
    assert isinstance(render_alerts([]), Table)


def test_alert_severity_colour_mapping():
    assert SEVERITY_STYLES["critical"] == "red"
    assert SEVERITY_STYLES["warn"] == "yellow"
    assert SEVERITY_STYLES["info"] == "cyan"
    table = render_alerts([AlertEvent(0.0, "critical", "syn_scan",
                                      "scan", "s", "d")])
    cell = table.columns[1]._cells[0]
    assert cell.plain == "critical"
    assert cell.style == "red"


# ----------------------------------------------------------------------
# Keyboard (non-blocking q -> stop event)
# ----------------------------------------------------------------------


class _FakeStdin:
    """A stand-in stdin exposing only a real fd (never a TTY here)."""

    def __init__(self, fd):
        self._fd = fd

    def fileno(self):
        return self._fd


def test_keyboard_q_sets_stop_event():
    read_fd, write_fd = os.pipe()
    stop = threading.Event()
    watcher = KeyboardWatcher(stop, stdin=_FakeStdin(read_fd),
                              poll_interval=0.01).start()
    try:
        os.write(write_fd, b"junk q junk")
        assert stop.wait(timeout=2.0), "q never set the stop event"
    finally:
        watcher.stop()
        os.close(read_fd)
        os.close(write_fd)


def test_keyboard_ignores_other_keys():
    read_fd, write_fd = os.pipe()
    stop = threading.Event()
    watcher = KeyboardWatcher(stop, stdin=_FakeStdin(read_fd),
                              poll_interval=0.01).start()
    try:
        os.write(write_fd, b"abc xyz")
        assert not stop.wait(timeout=0.3)
    finally:
        watcher.stop()
        os.close(read_fd)
        os.close(write_fd)


def test_keyboard_degrades_without_readable_stdin():
    stop = threading.Event()
    watcher = KeyboardWatcher(stop, stdin=object(), poll_interval=0.01).start()
    try:
        assert not stop.wait(timeout=0.2)
        time.sleep(0.05)  # let the thread finish its no-op path
        assert not watcher.alive
    finally:
        watcher.stop()


def test_keyboard_stop_before_q_is_clean():
    read_fd, write_fd = os.pipe()
    stop = threading.Event()
    watcher = KeyboardWatcher(stop, stdin=_FakeStdin(read_fd),
                              poll_interval=0.01).start()
    watcher.stop()  # must not raise even with a live fd
    os.close(read_fd)
    os.close(write_fd)


# ----------------------------------------------------------------------
# Dashboard (Layout + Live, snapshot-driven)
# ----------------------------------------------------------------------


def test_build_layout_has_all_regions():
    layout = build_layout(populated_store())
    assert isinstance(layout, Layout)
    for name in ("stream", "talkers", "telemetry", "alerts"):
        assert isinstance(layout[name], Layout)


def test_build_layout_empty_store_is_safe():
    layout = build_layout(StateStore())
    assert isinstance(layout, Layout)
    assert layout["stream"] is not None


def test_dashboard_render_returns_layout():
    dashboard = build_dashboard(populated_store())
    layout = dashboard.render()
    assert isinstance(layout, Layout)
    assert layout["stream"] is not None


def test_dashboard_start_stop_without_tty():
    dashboard = build_dashboard(populated_store(), refresh_per_second=50.0)
    dashboard.start()
    try:
        time.sleep(0.05)  # let the refresh thread tick
        assert dashboard.is_running
    finally:
        dashboard.stop()
    assert not dashboard.is_running


def test_dashboard_context_manager_without_tty():
    with build_dashboard(populated_store(), refresh_per_second=50.0):
        time.sleep(0.05)
    # clean exit is the whole point


def test_dashboard_rejects_bad_refresh_rate():
    try:
        build_dashboard(populated_store(), refresh_per_second=0.0)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for non-positive refresh")


# ----------------------------------------------------------------------
# Analyzer wiring
# ----------------------------------------------------------------------


def test_analyzer_no_ui_flag_default_and_explicit():
    parser = build_parser()
    assert parser.parse_args([]).no_ui is False
    assert parser.parse_args(["--no-ui"]).no_ui is True
