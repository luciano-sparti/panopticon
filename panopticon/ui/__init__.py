"""Rich terminal dashboard (Phase 4 + 5).

Exposes the snapshot-driven table renderers, the ``Layout`` + ``Live``
dashboard, the non-blocking keyboard watcher, and the interactive key
controls (selector, pin, tag, kill) that drive the dashboard footer.
"""

from .dashboard import Dashboard, build_dashboard, build_layout
from .keyboard import KeyboardWatcher
from .keys import PINNED_TAG, UIControls, legend_text
from .tables import (
    render_alerts,
    render_stream_table,
    render_telemetry,
    render_top_talkers,
)

__all__ = [
    "Dashboard",
    "KeyboardWatcher",
    "PINNED_TAG",
    "UIControls",
    "build_dashboard",
    "build_layout",
    "legend_text",
    "render_alerts",
    "render_stream_table",
    "render_telemetry",
    "render_top_talkers",
]
