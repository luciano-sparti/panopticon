"""Rich ``Layout`` + ``Live`` dashboard built from ``StateStore`` snapshots.

The dashboard never calls the store's mutation API: every refresh it pulls
fresh, copy-on-write snapshots (``StateStore.snapshot_*``) and renders them. It is
safe with an empty store and when stdout is not a terminal (headless/CI,
failed capture): Rich's ``Live`` degrades to a no-op there instead of
raising, so the analyzer never crashes because of the UI.
"""

from __future__ import annotations

import time
from collections import Counter, deque
from typing import Literal

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from typing_extensions import Self

from panopticon.core.store import StateStore

from .keys import VIEW_MODE_NAMES, UIControls, legend_text
from .tables import (
    DEFAULT_TOP_TALKERS,
    render_alerts,
    render_help,
    render_host_inspector,
    render_stream_table,
    render_telemetry,
    render_top_talkers,
)

DEFAULT_REFRESH_PER_SECOND = 1.0

# Peak decay factor: the bar-scaling peak forgets 5% per refresh tick so
# activity bars stay comparable after a burst passes.
PEAK_DECAY = 0.95

# Rolling samples kept for the telemetry sparkline rows.
SPARKLEN = 60


def render_footer(text: str) -> Text:
    """The persistent key-legend / inline-prompt footer line."""
    return Text(text or legend_text(), style="bold cyan")


def render_header(
    capture_info: dict | None = None,
    view_name: str = VIEW_MODE_NAMES[0],
    paused: bool = False,
    uptime: float | None = None,
) -> Text:
    """One-line capture context: iface, BPF filter, view, state, uptime."""
    header = Text(style="bold")
    header.append("panopticon", style="bold cyan")
    info = capture_info or {}
    if info.get("interface"):
        header.append(f" · iface {info['interface']}")
    if info.get("filter"):
        header.append(f" · filter {info['filter']!r}")
    header.append(f" · view {view_name}")
    mins, secs = divmod(int(uptime if uptime is not None else info.get("uptime") or 0), 60)
    hours, mins = divmod(mins, 60)
    header.append(f" · up {hours:02d}:{mins:02d}:{secs:02d}")
    header.append(" · ")
    header.append("FROZEN" if paused else "LIVE", style="bold yellow" if paused else "bold green")
    return header


def build_layout(
    store: StateStore,
    top_n: int = DEFAULT_TOP_TALKERS,
    controls: UIControls | None = None,
    stream_events: list | None = None,
    capture_info: dict | None = None,
    rates: dict[str, float] | None = None,
    bar_peak: float | None = None,
) -> Layout:
    """Build the dashboard ``Layout`` and populate it from live snapshots.

    Supports the capture-context header, full 4-pane layout, single-pane
    zoom modes (1-4), the help overlay, and the host inspector.
    """
    layout = Layout(name="root")
    view_mode = controls.view_mode if controls is not None else 0
    metric = controls.metric if controls is not None else "bytes"
    selected = controls.selected_ip if controls is not None else None
    inspecting_ip = controls.inspecting_ip if controls is not None else None
    paused = controls.paused if controls is not None else False

    events = stream_events if stream_events is not None else store.snapshot_stream()
    talkers = store.snapshot_talkers()
    telemetry = store.snapshot_telemetry()
    alerts = store.snapshot_alerts()
    footer = render_footer(controls.footer_text if controls is not None else "")
    view_name = VIEW_MODE_NAMES.get(view_mode, VIEW_MODE_NAMES[0])
    header = render_header(
        capture_info=capture_info,
        view_name=view_name,
        paused=paused,
        uptime=(capture_info or {}).get("uptime"),
    )

    def split_with_header(*rows) -> None:
        """Split root into header + given rows + footer."""
        parts = [Layout(name="header", size=1)]
        for name, spec in rows:
            parts.append(Layout(name=name, **spec))
        parts.append(Layout(name="footer", size=1))
        layout.split_column(*parts)

    if controls is not None and controls.help_visible:
        # Dismissible key-reference overlay
        split_with_header(("help", {"ratio": 1}))
        layout["help"].update(Panel(render_help(controls.enable_kill)))
        layout["footer"].update(footer)
        layout["header"].update(header)
        return layout

    if inspecting_ip:
        # Inspector overlay; per-host extras derived from the stream buffer
        host_events = [e for e in events if e.src == inspecting_ip or e.dst == inspecting_ip]
        ports = sorted(
            {e.dport for e in host_events if e.dst == inspecting_ip and e.dport}
            | {e.sport for e in host_events if e.src == inspecting_ip and e.sport}
        )
        proto_mix = dict(Counter(e.proto for e in host_events))
        first_seen = min((e.timestamp for e in host_events), default=None)
        flow = store.snapshot_flow(inspecting_ip)
        sessions = store.snapshot_sessions(ip=inspecting_ip, limit=20)
        talker_data = talkers.get(inspecting_ip)
        tags = store.tags_for(inspecting_ip)
        split_with_header(("inspector", {"ratio": 1}))
        layout["inspector"].update(
            Panel(
                render_host_inspector(
                    inspecting_ip,
                    talker_data=talker_data,
                    flow_data=flow,
                    tags=sorted(tags),
                    alerts=alerts,
                    ports_contacted=ports,
                    proto_mix=proto_mix,
                    first_seen=first_seen,
                    sessions=sessions,
                ),
                title=f"Inspector — {inspecting_ip}",
            )
        )
        layout["footer"].update(footer)
        layout["header"].update(header)
        return layout

    stream_title = "Stream [⏸ PAUSED]" if paused else "Stream [LIVE]"
    stream_panel = Panel(
        render_stream_table(events, self_ips=store.self_ips()),
        title=stream_title,
    )
    talkers_panel = Panel(
        render_top_talkers(
            talkers,
            top_n=top_n,
            metric=metric,
            selected=selected,
            rates=rates,
            bar_peak=bar_peak,
        ),
        title="Talkers",
    )
    telemetry_panel = Panel(render_telemetry(telemetry), title="Telemetry")

    crit_count = sum(1 for a in alerts if a.severity.lower() == "critical")
    filter_label = {
        None: "",
        "warn": " · filter warn+",
        "critical": " · filter critical",
    }.get(controls.alert_filter if controls is not None else None, "")
    alerts_title = f"Alerts ({crit_count} crit / {len(alerts)}){filter_label}"
    alerts_panel = Panel(
        render_alerts(
            alerts,
            min_severity=controls.alert_filter if controls is not None else None,
        ),
        title=alerts_title,
    )

    if view_mode == 1:
        # Stream zoom
        split_with_header(("stream", {"ratio": 1}))
        layout["stream"].update(stream_panel)
        _finish(layout, footer, header)
        return layout

    if view_mode == 2:
        # Talkers zoom
        split_with_header(("talkers", {"ratio": 1}))
        layout["talkers"].update(talkers_panel)
        _finish(layout, footer, header)
        return layout

    if view_mode == 3:
        # Alerts zoom
        split_with_header(("alerts", {"ratio": 1}))
        layout["alerts"].update(alerts_panel)
        _finish(layout, footer, header)
        return layout

    if view_mode == 4:
        # Telemetry zoom
        split_with_header(("telemetry", {"ratio": 1}))
        layout["telemetry"].update(telemetry_panel)
        _finish(layout, footer, header)
        return layout

    # Default 4-pane layout
    split_with_header(
        ("stream", {"ratio": 3}),
        ("bottom", {"ratio": 2}),
    )
    layout["bottom"].split_row(
        Layout(name="talkers", ratio=2),
        Layout(name="right", ratio=1),
    )
    layout["right"].split_column(
        Layout(name="telemetry", ratio=1),
        Layout(name="alerts", ratio=1),
    )

    layout["stream"].update(stream_panel)
    layout["talkers"].update(talkers_panel)
    layout["telemetry"].update(telemetry_panel)
    layout["alerts"].update(alerts_panel)
    _finish(layout, footer, header)
    return layout


def _finish(layout: Layout, footer: Text, header: Text) -> None:
    """Populate the shared header/footer regions of a built layout."""
    layout["footer"].update(footer)
    layout["header"].update(header)


class Dashboard:
    """Owns a Rich ``Live`` that re-renders the snapshot layout on a timer.

    Also derives UI-only analytics between refresh ticks: per-talker byte
    rates (snapshot diffs), a decaying bar-scaling peak, and the rolling
    velocity sparkline samples.
    """

    def __init__(
        self,
        store: StateStore,
        *,
        refresh_per_second: float = DEFAULT_REFRESH_PER_SECOND,
        console: Console | None = None,
        top_n: int = DEFAULT_TOP_TALKERS,
        controls: UIControls | None = None,
        capture_info: dict | None = None,
    ) -> None:
        if refresh_per_second <= 0:
            raise ValueError("refresh_per_second must be positive")
        self._store = store
        self._top_n = top_n
        self._controls = controls
        self._console = console if console is not None else Console()
        self._refresh_per_second = refresh_per_second
        self._capture_info = dict(capture_info) if capture_info else {}
        self._live: Live | None = None
        self._frozen_stream: list | None = None
        self._started_at: float | None = None
        self._prev_talkers: dict[str, dict] | None = None
        self._prev_rates_at: float | None = None
        self._peak: float = 0.0
        self._spark: deque[tuple[float, float]] = deque(maxlen=SPARKLEN)

    @property
    def console(self) -> Console:
        """The Console the dashboard renders onto."""
        return self._console

    @property
    def is_running(self) -> bool:
        """True while the Live display is active."""
        return self._live is not None

    def _derive_analytics(self, talkers, telemetry):
        """Per-talker rates, decaying peak, sparkline sample (per tick)."""
        now = time.monotonic()
        rates: dict[str, float] = {}
        if (
            not (self._controls is not None and self._controls.paused)
            and self._prev_talkers is not None
            and self._prev_rates_at is not None
        ):
            dt = now - self._prev_rates_at
            if dt > 0:
                for ip, stats in talkers.items():
                    prev = self._prev_talkers.get(ip)
                    if prev:
                        delta = stats.get("bytes", 0) - prev.get("bytes", 0)
                        rates[ip] = max(0.0, delta / dt)
            pps = telemetry.get("packets_per_sec", 0.0)
            bps = telemetry.get("bytes_per_sec", 0.0)
            self._spark.append((pps, bps))
        elif not (self._controls is not None and self._controls.paused):
            self._spark.clear()
        self._prev_talkers = talkers
        self._prev_rates_at = now

        metric = self._controls.metric if self._controls is not None else "bytes"
        current_max = max((stats.get(metric, 0) for stats in talkers.values()), default=0)
        self._peak = max(float(current_max), self._peak * PEAK_DECAY)
        return rates

    def render(self) -> Layout:
        """Build the current snapshot layout (called by the Live refresh thread)."""
        is_paused = self._controls.paused if self._controls is not None else False
        if is_paused:
            if self._frozen_stream is None:
                self._frozen_stream = self._store.snapshot_stream()
            stream_events = self._frozen_stream
        else:
            self._frozen_stream = None
            stream_events = self._store.snapshot_stream()

        talkers = self._store.snapshot_talkers()
        telemetry = self._store.snapshot_telemetry()
        rates = self._derive_analytics(talkers, telemetry)

        info = dict(self._capture_info)
        if self._started_at is not None:
            info["uptime"] = time.monotonic() - self._started_at

        return build_layout(
            self._store,
            self._top_n,
            self._controls,
            stream_events=stream_events,
            capture_info=info,
            rates=rates,
            bar_peak=self._peak,
        )

    def start(self) -> None:
        """Enter alternate-screen live mode and begin auto-refreshing."""
        if self._live is not None:
            return
        self._started_at = time.monotonic()
        self._live = Live(
            console=self._console,
            screen=True,
            auto_refresh=True,
            refresh_per_second=self._refresh_per_second,
            get_renderable=self.render,
        )
        self._live.start()

    def stop(self) -> None:
        """Leave alternate-screen live mode and stop the refresh thread."""
        if self._live is not None:
            self._live.stop()
            self._live = None

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> Literal[False]:
        self.stop()
        return False


def build_dashboard(
    store: StateStore,
    *,
    refresh_per_second: float = DEFAULT_REFRESH_PER_SECOND,
    console: Console | None = None,
    top_n: int = DEFAULT_TOP_TALKERS,
    controls: UIControls | None = None,
    capture_info: dict | None = None,
) -> Dashboard:
    """Create a dashboard for ``store`` (snapshots only, no mutation)."""
    return Dashboard(
        store,
        refresh_per_second=refresh_per_second,
        console=console,
        top_n=top_n,
        controls=controls,
        capture_info=capture_info,
    )
