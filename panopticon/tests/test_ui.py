"""Phase 4 UI tests: snapshot -> Rich renderables, keyboard watcher, dashboard.

Every test runs without a TTY, exercising the "no-root safety" path: the
dashboard, renderers, and keyboard watcher must degrade gracefully, never
raise, and never block on ``input()``.
"""

import io
import os
import signal as sig
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
    UIControls,
    build_dashboard,
    build_layout,
    legend_text,
    render_alerts,
    render_header,
    render_stream_table,
    render_telemetry,
    render_top_talkers,
)
from panopticon.ui.dashboard import render_footer
from panopticon.ui.keys import PINNED_TAG
from panopticon.ui.tables import SEVERITY_STYLES, _fmt_bytes, rank_talkers


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
    assert "crit" in cell.plain
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


def test_keyboard_forwards_keys_to_on_key():
    read_fd, write_fd = os.pipe()
    seen = []
    stop = threading.Event()
    watcher = KeyboardWatcher(
        stop,
        stdin=_FakeStdin(read_fd),
        poll_interval=0.01,
        on_key=seen.append,
    ).start()
    try:
        os.write(write_fd, b"pt")
        deadline = time.monotonic() + 2.0
        while not seen and time.monotonic() < deadline:
            time.sleep(0.01)
        assert b"".join(seen) == b"pt"
        assert not stop.is_set()  # p/t are not quit keys
    finally:
        watcher.stop()
        os.close(read_fd)
        os.close(write_fd)


def test_keyboard_handler_error_does_not_kill_watcher():
    def _boom(_data):
        raise RuntimeError("handler bug")

    read_fd, write_fd = os.pipe()
    stop = threading.Event()
    watcher = KeyboardWatcher(
        stop,
        stdin=_FakeStdin(read_fd),
        poll_interval=0.01,
        on_key=_boom,
    ).start()
    try:
        os.write(write_fd, b"abc")
        assert not stop.wait(timeout=0.5)
    finally:
        watcher.stop()
        os.close(read_fd)
        os.close(write_fd)


# ----------------------------------------------------------------------
# Phase 5: legend footer, selector, pin, tag, kill
# ----------------------------------------------------------------------


def _talker_store():
    store = StateStore()
    for i in range(5):
        store.update(ev(float(i), src=f"10.0.0.{i + 1}", size=100 + i * 10))
    return store


def test_legend_text_shows_kill_only_when_enabled():
    assert "k kill" not in legend_text(False)
    assert "k kill" in legend_text(True)
    for key in ("q quit", "↑/↓ select", "p pin", "t tag", "T untag", "? help"):
        assert key in legend_text(False)


def test_render_footer_renders_legend_and_prompt():
    assert "q quit" in render_text(render_footer(""))
    assert "tag 10.0.0.1: web" in render_text(render_footer("tag 10.0.0.1: web"))


def test_build_layout_has_footer_region():
    layout = build_layout(_talker_store())
    assert layout["footer"] is not None


def test_layout_footer_reflects_controls_prompt():
    store = _talker_store()
    controls = UIControls(store)
    controls.selected_ip = "10.0.0.1"
    controls.prompt = {"kind": "add", "ip": "10.0.0.1", "buffer": "web"}
    text = render_text(build_layout(store, controls=controls))
    assert "tag 10.0.0.1: web" in text


def test_rank_talkers_pins_first_then_bytes():
    talkers = {
        "small": {"pkts": 1, "bytes": 10, "tags": []},
        "big": {"pkts": 2, "bytes": 100, "tags": []},
        "pin": {"pkts": 3, "bytes": 50, "tags": ["pinned"]},
    }
    assert [ip for ip, _ in rank_talkers(talkers)] == ["pin", "big", "small"]


def test_pinned_talker_renders_first_with_caption():
    store = StateStore()
    for i in range(3):
        store.update(ev(0.0, src=f"ip{i}", size=100 * (i + 1)))
    store.add_tag("ip0", PINNED_TAG)
    table = render_top_talkers(store.snapshot_talkers())
    text = render_text(table)
    assert text.index("ip0") < text.index("ip2")
    assert "Pinned: ip0" in text
    assert "pinned" in text


def test_selected_talker_is_highlighted():
    store = StateStore()
    store.update(ev(0.0, src="ip0", size=100))
    table = render_top_talkers(store.snapshot_talkers(), selected="ip0")
    assert "▸ ip0" in render_text(table)


def test_selector_moves_on_arrow_keys():
    controls = UIControls(_talker_store())
    controls.feed(b"\x1b[B")
    assert controls.selected_ip == "10.0.0.5"
    controls.feed(b"\x1b[B")
    assert controls.selected_ip == "10.0.0.4"
    controls.feed(b"\x1b[A")
    assert controls.selected_ip == "10.0.0.5"


def test_selector_moves_on_j():
    controls = UIControls(_talker_store())
    controls.feed(b"j")
    assert controls.selected_ip == "10.0.0.5"


def test_selector_clamps_at_edges():
    controls = UIControls(_talker_store())
    for _ in range(10):
        controls.feed(b"\x1b[B")
    assert controls.selected_ip == "10.0.0.1"
    for _ in range(10):
        controls.feed(b"\x1b[A")
    assert controls.selected_ip == "10.0.0.5"


def test_selector_with_empty_store_is_safe():
    controls = UIControls(StateStore())
    controls.feed(b"\x1b[B")
    assert controls.selected_ip is None


def test_pin_toggles_tag_on_selected():
    store = _talker_store()
    controls = UIControls(store)
    controls.feed(b"\x1b[B")
    controls.feed(b"p")
    assert "pinned" in store.tags_for("10.0.0.5")
    controls.feed(b"p")
    assert "pinned" not in store.tags_for("10.0.0.5")


def test_pin_without_selection_shows_status():
    controls = UIControls(StateStore())
    controls.feed(b"p")
    assert "no talker selected" in controls.status


def test_t_adds_tag_via_inline_prompt():
    store = _talker_store()
    controls = UIControls(store)
    controls.feed(b"\x1b[B")
    controls.feed(b"t")
    assert controls.prompt is not None
    for ch in b"web-server":
        controls.feed(bytes([ch]))
    assert controls.prompt_text == "tag 10.0.0.5: web-server▏"
    controls.feed(b"\r")
    assert controls.prompt is None
    assert "web-server" in store.tags_for("10.0.0.5")


def test_t_prompt_backspace_edits_buffer():
    store = _talker_store()
    controls = UIControls(store)
    controls.feed(b"\x1b[B")
    controls.feed(b"t")
    for ch in b"abcd":
        controls.feed(bytes([ch]))
    controls.feed(b"\x7f")
    controls.feed(b"\r")
    assert "abc" in store.tags_for("10.0.0.5")


def test_T_removes_tag_via_inline_prompt():
    store = _talker_store()
    store.add_tag("10.0.0.5", "manual")
    controls = UIControls(store)
    controls.feed(b"\x1b[B")
    controls.feed(b"T")
    for ch in b"manual":
        controls.feed(bytes([ch]))
    controls.feed(b"\r")
    assert "manual" not in store.tags_for("10.0.0.5")


def test_t_without_selection_shows_status():
    controls = UIControls(StateStore())
    controls.feed(b"t")
    assert "no talker selected" in controls.status
    assert controls.prompt is None


def test_k_is_noop_without_enable_kill():
    store = _talker_store()
    controls = UIControls(store, enable_kill=False)
    controls.feed(b"\x1b[B")
    controls.feed(b"k")
    assert controls.prompt is None
    assert "kill disabled" in controls.status


def test_k_without_known_flow_shows_status():
    store = StateStore(self_ips={"10.0.0.1"}, self_host="host")
    store.update(ev(0.0, src="10.0.0.2", dst="10.0.0.5"), now=0.0)
    controls = UIControls(store, enable_kill=True,
                          kill_resolver=lambda ip, port: [1])
    controls.feed(b"\x1b[B")
    controls.feed(b"k")
    assert controls.prompt is None
    assert "no known flow" in controls.status


def test_k_confirms_and_signals_selected_flow(monkeypatch):
    store = StateStore(self_ips={"10.0.0.1"}, self_host="host")
    store.update(ev(0.0, src="10.0.0.1", dst="10.0.0.5",
                    sport=40000, dport=8080, size=100), now=0.0)
    store.update(ev(1.0, src="10.0.0.5", dst="10.0.0.1",
                    sport=8080, dport=40000, size=200), now=1.0)
    sent = []
    monkeypatch.setattr("panopticon.ui.keys.os.kill",
                        lambda pid, _sig: sent.append(pid))
    controls = UIControls(store, enable_kill=True,
                          kill_resolver=lambda ip, port: [123, 456])
    controls.feed(b"\x1b[B")
    controls.feed(b"k")
    assert controls.prompt["kind"] == "confirm"
    assert "kill 10.0.0.5 via local port 40000" in controls.prompt_text
    controls.feed(b"y")
    assert controls.prompt is None
    assert sent == [123, 456]
    assert "SIGTERM" in controls.status


def test_k_confirm_n_aborts(monkeypatch):
    store = StateStore(self_ips={"10.0.0.1"}, self_host="host")
    store.update(ev(0.0, src="10.0.0.1", dst="10.0.0.5",
                    sport=40000, dport=8080, size=100), now=0.0)
    store.update(ev(1.0, src="10.0.0.5", dst="10.0.0.1",
                    sport=8080, dport=40000, size=200), now=1.0)
    sent = []
    monkeypatch.setattr("panopticon.ui.keys.os.kill",
                        lambda pid, _sig: sent.append(pid))
    controls = UIControls(store, enable_kill=True,
                          kill_resolver=lambda ip, port: [123])
    controls.feed(b"\x1b[B")
    controls.feed(b"k")
    controls.feed(b"n")
    assert controls.prompt is None
    assert sent == []


def test_help_key_toggles_overlay():
    controls = UIControls(_talker_store())
    assert not controls.help_visible
    controls.feed(b"?")
    assert controls.help_visible
    # Any other key dismisses the overlay without acting underneath.
    controls.feed(b"p")
    assert not controls.help_visible
    assert controls.status == ""  # pin did NOT fire while overlay open


def test_help_overlay_renders_in_layout():
    store = _talker_store()
    controls = UIControls(store)
    controls.selected_ip = "10.0.0.1"
    controls.help_visible = True
    layout = build_layout(store, controls=controls)
    assert layout.get("help") is not None
    text = render_text(layout["help"])
    assert "Help" in text and "quit" in text
    # Footer legend still available underneath.
    assert "q quit" in render_text(layout["footer"])


def test_esc_closes_help_then_clears_selection():
    store = _talker_store()
    controls = UIControls(store)
    controls.selected_ip = "10.0.0.1"
    controls.help_visible = True
    controls.feed(b"\x1b")  # lone Esc arrives as its own chunk
    assert controls.help_visible is False
    assert controls.selected_ip == "10.0.0.1"  # first Esc closes overlay
    controls.feed(b"\x1b")
    assert controls.selected_ip is None  # second Esc clears selection


def test_ctrl_n_p_move_selection():
    store = populated_store()
    controls = UIControls(store)
    controls.feed(b"\x0e")  # Ctrl+N -> down -> first talker
    first = controls.selected_ip
    assert first is not None
    controls.feed(b"\x10")  # Ctrl+P -> up -> back to none-selected position
    assert controls.selected_ip == first  # clamped at top edge


def test_alert_filter_cycles_and_filters():
    controls = UIControls(populated_store())
    assert controls.alert_filter is None
    controls.feed(b"!")
    assert controls.alert_filter == "warn"
    controls.feed(b"!")
    assert controls.alert_filter == "critical"
    controls.feed(b"!")
    assert controls.alert_filter is None


def test_render_alerts_min_severity_filter():
    alerts = populated_store().snapshot_alerts()
    text_all = render_text(render_alerts(alerts))
    assert "syn_scan" in text_all and "plaintext" in text_all
    crit_only = render_text(render_alerts(alerts, min_severity="critical"))
    assert "plaintext" in crit_only and "syn_scan" not in crit_only
    empty_crit = render_text(render_alerts([], min_severity="critical"))
    assert "no critical alerts" in empty_crit


def test_fmt_bytes_humanized():
    assert _fmt_bytes(0) == "0 B"
    assert _fmt_bytes(512) == "512 B"
    assert _fmt_bytes(2048) == "2.0 KiB"
    assert _fmt_bytes(5 * 1024 * 1024) == "5.0 MiB"


def test_top_talkers_rates_and_peak_params():
    store = populated_store()
    table = render_top_talkers(
        store.snapshot_talkers(),
        rates={"10.0.0.5": 1024.0},
        bar_peak=1000,
    )
    text = render_text(table)
    assert "Rate" in text
    assert "1.0 KiB/s" in text


def test_header_renders_capture_context():
    header = render_header(
        capture_info={"interface": "eno1", "filter": "tcp", "uptime": 3720},
        view_name="all panes",
        paused=False,
    )
    text = render_text(header)
    assert "iface eno1" in text and "filter 'tcp'" in text
    assert "up 01:02:00" in text and "LIVE" in text
    frozen = render_text(render_header(paused=True))
    assert "FROZEN" in frozen


def test_layout_has_header_region():
    layout = build_layout(_talker_store(), controls=None)
    assert layout.get("header") is not None
    assert "panopticon" in render_text(layout["header"])


def test_inspector_shows_ports_protocols_first_seen():
    from panopticon.core.event import PacketEvent

    store = StateStore()
    for i, (src, dst, dport, proto) in enumerate([
        ("10.9.9.9", "8.8.8.8", 443, "tcp"),
        ("10.9.9.9", "8.8.4.4", 53, "udp"),
        ("8.8.8.8", "10.9.9.9", 50000, "tcp"),
    ]):
        store.update(PacketEvent(float(i), src, dst, proto, 40000 + i,
                                 dport if dst != "10.9.9.9" else 12345,
                                 100, ""))
    controls = UIControls(store)
    controls.inspecting_ip = "10.9.9.9"
    layout = build_layout(store, controls=controls)
    text = render_text(layout["inspector"], width=160)
    assert "First Seen" in text
    assert "Ports Contacted" in text
    assert "Protocol Mix" in text


def test_dashboard_derives_rates_sparkline_and_uptime():
    store = _talker_store()
    controls = UIControls(store)
    dash = build_dashboard(store, refresh_per_second=10, controls=controls)
    dash.render()  # baseline tick
    store.update(ev(99.0, src="10.0.0.1", size=10000))
    dash.render()  # delta tick -> rate derived
    assert dash._spark, "sparkline should collect samples after two ticks"
    assert dash._peak >= 0


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


# ----------------------------------------------------------------------
# New UI/UX Accessibility & Ergonomics Tests
# ----------------------------------------------------------------------


def test_stream_freeze_toggle_caches_rendered_stream():
    store = populated_store()
    controls = UIControls(store)
    dashboard = build_dashboard(store, controls=controls)

    # Initial render
    layout1 = dashboard.render()
    assert "[LIVE]" in render_text(layout1["stream"])

    # Toggle pause
    controls.feed(b" ")
    assert controls.paused is True
    assert "FROZEN" in controls.status

    layout2 = dashboard.render()
    assert "[⏸ PAUSED]" in render_text(layout2["stream"])

    # Push new event into store
    store.update(ev(99.0, src="10.0.0.99", size=999), now=99.0)

    # While paused, rendered stream remains frozen
    layout3 = dashboard.render()
    assert "10.0.0.99" not in render_text(layout3["stream"])

    # Unpause
    controls.feed(b" ")
    assert controls.paused is False
    layout4 = dashboard.render()
    assert "10.0.0.99" in render_text(layout4["stream"])


def test_metric_toggle_flips_sorting_and_selector_order():
    store = StateStore()
    # ipA: 10 packets, 100 bytes
    # ipB: 1 packet, 1000 bytes
    for _ in range(10):
        store.update(ev(0.0, src="ipA", size=10), now=0.0)
    store.update(ev(0.0, src="ipB", size=1000), now=0.0)

    controls = UIControls(store)
    # Default is bytes: ipB (1000 B) > ipA (100 B)
    assert controls._ordered_talkers() == ["ipB", "ipA"]

    # Toggle metric to pkts
    controls.feed(b"m")
    assert controls.metric == "pkts"
    assert "pkts" in controls.status
    # With pkts: ipA (10 pkts) > ipB (1 pkt)
    assert controls._ordered_talkers() == ["ipA", "ipB"]


def test_zoom_view_modes_render_focused_panels():
    store = populated_store()
    controls = UIControls(store)

    # 1: Stream zoom
    controls.feed(b"1")
    assert controls.view_mode == 1
    layout = build_layout(store, controls=controls)
    assert layout.get("stream") is not None
    assert layout.get("talkers") is None

    # 2: Talkers zoom
    controls.feed(b"2")
    assert controls.view_mode == 2
    layout = build_layout(store, controls=controls)
    assert layout.get("talkers") is not None
    assert layout.get("stream") is None

    # 3: Alerts zoom
    controls.feed(b"3")
    assert controls.view_mode == 3
    layout = build_layout(store, controls=controls)
    assert layout.get("alerts") is not None
    assert layout.get("stream") is None

    # 4: Telemetry zoom
    controls.feed(b"4")
    assert controls.view_mode == 4
    layout = build_layout(store, controls=controls)
    assert layout.get("telemetry") is not None
    assert layout.get("stream") is None

    # 0: Reset to all
    controls.feed(b"0")
    assert controls.view_mode == 0
    layout = build_layout(store, controls=controls)
    assert layout.get("stream") is not None
    assert layout.get("talkers") is not None
    assert layout.get("alerts") is not None


def test_tab_cycles_view_modes():
    controls = UIControls(StateStore())
    assert controls.view_mode == 0
    controls.feed(b"\t")
    assert controls.view_mode == 1
    controls.feed(b"\t")
    assert controls.view_mode == 2
    controls.feed(b"\t")
    assert controls.view_mode == 3
    controls.feed(b"\t")
    assert controls.view_mode == 4
    controls.feed(b"\t")
    assert controls.view_mode == 0


def test_host_inspector_toggle_and_render():
    store = populated_store()
    controls = UIControls(store)
    controls.selected_ip = "10.0.0.1"

    # Press Enter to open inspector
    controls.feed(b"\r")
    assert controls.inspecting_ip == "10.0.0.1"

    layout = build_layout(store, controls=controls)
    assert layout.get("inspector") is not None
    text = render_text(layout["inspector"])
    assert "Host Inspection: 10.0.0.1" in text
    assert "Total Packets" in text

    # Press Enter again to close
    controls.feed(b"\r")
    assert controls.inspecting_ip is None



def test_stream_table_with_direction_indicators():
    events = [
        ev(1.0, src="192.168.1.10", dst="8.8.8.8"),
        ev(2.0, src="8.8.8.8", dst="192.168.1.10"),
        ev(3.0, src="192.168.1.10", dst="192.168.1.10"),
    ]
    self_ips = {"192.168.1.10"}
    table = render_stream_table(events, self_ips=self_ips)
    text = render_text(table)
    assert "Dir" in text
    assert "▲" in text  # Outbound
    assert "▼" in text  # Inbound
    assert "↔" in text  # Internal


def test_multi_state_talker_pinned_and_selected():
    store = StateStore()
    store.update(ev(0.0, src="10.0.0.1", size=100))
    store.add_tag("10.0.0.1", PINNED_TAG)
    table = render_top_talkers(store.snapshot_talkers(), selected="10.0.0.1")
    text = render_text(table)
    assert "▸ ● 10.0.0.1" in text

