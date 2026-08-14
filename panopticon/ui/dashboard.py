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

from panopticon.core.store import StateStore

from .tables import (
    DEFAULT_TOP_TALKERS,
    render_alerts,
    render_stream_table,
    render_telemetry,
    render_top_talkers,
)

DEFAULT_REFRESH_PER_SECOND = 1.0


def build_layout(store: StateStore, top_n: int = DEFAULT_TOP_TALKERS) -> Layout:
    """Build the dashboard ``Layout`` and populate it from live snapshots.

    Top: rolling stream table. Bottom, split row: top talkers on the left,
    telemetry + alerts stacked on the right.
    """
    layout = Layout(name="root")
    layout.split_column(
        Layout(name="stream", ratio=3),
        Layout(name="bottom", ratio=2),
    )
    layout["bottom"].split_row(
        Layout(name="talkers", ratio=2),
        Layout(name="right", ratio=1),
    )
    layout["right"].split_column(
        Layout(name="telemetry", ratio=1),
        Layout(name="alerts", ratio=1),
    )

    layout["stream"].update(
        Panel(render_stream_table(store.snapshot_stream()), title="Stream")
    )
    layout["talkers"].update(
        Panel(render_top_talkers(store.snapshot_talkers(), top_n=top_n), title="Talkers")
    )
    layout["telemetry"].update(
        Panel(render_telemetry(store.snapshot_telemetry()), title="Telemetry")
    )
    layout["alerts"].update(
        Panel(render_alerts(store.snapshot_alerts()), title="Alerts")
    )
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
    ) -> None:
        if refresh_per_second <= 0:
            raise ValueError("refresh_per_second must be positive")
        self._store = store
        self._top_n = top_n
        self._console = console if console is not None else Console()
        self._refresh_per_second = refresh_per_second
        self._live: Optional[Live] = None

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
        return build_layout(self._store, self._top_n)

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
) -> Dashboard:
    """Create a dashboard for ``store`` (snapshots only, no mutation)."""
    return Dashboard(
        store,
        refresh_per_second=refresh_per_second,
        console=console,
        top_n=top_n,
    )
