"""Rich terminal dashboard (Phase 4).

Exposes the snapshot-driven table renderers, the ``Layout`` + ``Live``
dashboard, and the non-blocking keyboard watcher used by the analyzer CLI.
"""

from .dashboard import Dashboard, build_dashboard, build_layout
from .keyboard import KeyboardWatcher
from .tables import (
    render_alerts,
    render_stream_table,
    render_telemetry,
    render_top_talkers,
)

__all__ = [
    "Dashboard",
    "KeyboardWatcher",
    "build_dashboard",
    "build_layout",
    "render_alerts",
    "render_stream_table",
    "render_telemetry",
    "render_top_talkers",
]
