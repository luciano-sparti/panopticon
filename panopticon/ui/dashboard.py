"""Rich ``Layout`` + ``Live`` dashboard built from ``StateStore`` snapshots.

The dashboard never calls the store's mutation API: every refresh it pulls
deep-copied snapshots (``StateStore.snapshot_*``) and renders them. It is
safe with an empty store and when stdout is not a terminal (headless/CI,
failed capture): Rich's ``Live`` degrades to a no-op there instead of
raising, so the analyzer never crashes because of the UI.
"""

from __future__ import annotations

from typing import Optional

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from panopticon.core.store import StateStore

from .keys import UIControls, legend_text
from .tables import (
    DEFAULT_TOP_TALKERS,
    render_alerts,
    render_host_inspector,
    render_stream_table,
    render_telemetry,
    render_top_talkers,
)

DEFAULT_REFRESH_PER_SECOND = 1.0


def render_footer(text: str) -> Text:
    """The persistent key-legend / inline-prompt footer line."""
    return Text(text or legend_text(), style="bold cyan")


def build_layout(
    store: StateStore,
    top_n: int = DEFAULT_TOP_TALKERS,
    controls: Optional[UIControls] = None,
    stream_events: Optional[list] = None,
) -> Layout:
    """Build the dashboard ``Layout`` and populate it from live snapshots.

    Supports full 4-pane layout, single-pane zoom modes (1-4), and the
    interactive host inspector overlay.
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

    if inspecting_ip:
        # Inspector overlay
        layout.split_column(
            Layout(name="inspector", ratio=1),
            Layout(name="footer", size=1),
        )
        flow = store.snapshot_flow(inspecting_ip)
        talker_data = talkers.get(inspecting_ip)
        tags = store.tags_for(inspecting_ip)
        layout["inspector"].update(
            Panel(
                render_host_inspector(
                    inspecting_ip,
                    talker_data=talker_data,
                    flow_data=flow,
                    tags=sorted(tags),
                    alerts=alerts,
                ),
                title=f"Inspector — {inspecting_ip}",
            )
        )
        layout["footer"].update(footer)
        return layout

    stream_title = "Stream [⏸ PAUSED]" if paused else "Stream [LIVE]"
    stream_panel = Panel(render_stream_table(events), title=stream_title)
    talkers_panel = Panel(
        render_top_talkers(talkers, top_n=top_n, metric=metric, selected=selected),
        title="Talkers",
    )
    telemetry_panel = Panel(render_telemetry(telemetry), title="Telemetry")
    alerts_panel = Panel(render_alerts(alerts), title="Alerts")

    if view_mode == 1:
        # Stream zoom
        layout.split_column(
            Layout(name="stream", ratio=1),
            Layout(name="footer", size=1),
        )
        layout["stream"].update(stream_panel)
        layout["footer"].update(footer)
        return layout

    if view_mode == 2:
        # Talkers zoom
        layout.split_column(
            Layout(name="talkers", ratio=1),
            Layout(name="footer", size=1),
        )
        layout["talkers"].update(talkers_panel)
        layout["footer"].update(footer)
        return layout

    if view_mode == 3:
        # Alerts zoom
        layout.split_column(
            Layout(name="alerts", ratio=1),
            Layout(name="footer", size=1),
        )
        layout["alerts"].update(alerts_panel)
        layout["footer"].update(footer)
        return layout

    if view_mode == 4:
        # Telemetry zoom
        layout.split_column(
            Layout(name="telemetry", ratio=1),
            Layout(name="footer", size=1),
        )
        layout["telemetry"].update(telemetry_panel)
        layout["footer"].update(footer)
        return layout

    # Default 4-pane layout
    layout.split_column(
        Layout(name="stream", ratio=3),
        Layout(name="bottom", ratio=2),
        Layout(name="footer", size=1),
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
    layout["footer"].update(footer)
    return layout



class Dashboard:
    """Owns a Rich ``Live`` that re-renders the snapshot layout on a timer."""

    def __init__(
        self,
        store: StateStore,
        *,
        refresh_per_second: float = DEFAULT_REFRESH_PER_SECOND,
        console: Optional[Console] = None,
        top_n: int = DEFAULT_TOP_TALKERS,
        controls: Optional[UIControls] = None,
    ) -> None:
        if refresh_per_second <= 0:
            raise ValueError("refresh_per_second must be positive")
        self._store = store
        self._top_n = top_n
        self._controls = controls
        self._console = console if console is not None else Console()
        self._refresh_per_second = refresh_per_second
        self._live: Optional[Live] = None
        self._frozen_stream: Optional[list] = None

    @property
    def console(self) -> Console:
        """The Console the dashboard renders onto."""
        return self._console

    @property
    def is_running(self) -> bool:
        """True while the Live display is active."""
        return self._live is not None

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

        return build_layout(
            self._store,
            self._top_n,
            self._controls,
            stream_events=stream_events,
        )


    def start(self) -> None:
        """Enter alternate-screen live mode and begin auto-refreshing."""
        if self._live is not None:
            return
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

    def __enter__(self) -> "Dashboard":
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.stop()
        return False


def build_dashboard(
    store: StateStore,
    *,
    refresh_per_second: float = DEFAULT_REFRESH_PER_SECOND,
    console: Optional[Console] = None,
    top_n: int = DEFAULT_TOP_TALKERS,
    controls: Optional[UIControls] = None,
) -> Dashboard:
    """Create a dashboard for ``store`` (snapshots only, no mutation)."""
    return Dashboard(
        store,
        refresh_per_second=refresh_per_second,
        console=console,
        top_n=top_n,
        controls=controls,
    )
