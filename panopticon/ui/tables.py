"""StateStore snapshot -> Rich renderable renderers.

Every renderer takes a deep-copied snapshot from ``StateStore.snapshot_*``
and returns a ``rich`` renderable (a ``Table``). Renderers never touch the
store or its mutation API and never block on pipeline state, so they are
safe to call from the UI refresh thread at any cadence.
"""

from __future__ import annotations

import datetime
from typing import Dict, List

from rich.table import Table
from rich.text import Text

from panopticon.core.event import AlertEvent, PacketEvent

# Density levels for the ASCII activity bars (coarsest -> densest).
BAR_CHARS = "▁▂▃▄▅▆▇█"
# Severity -> colour/style mapping used by ``render_alerts``.
SEVERITY_STYLES = {
    "info": "cyan",
    "warn": "yellow",
    "critical": "red",
}

DEFAULT_TOP_TALKERS = 10
BAR_WIDTH = 10


def _fmt_time(ts: float) -> str:
    """Format an epoch timestamp as HH:MM:SS.mmm."""
    dt = datetime.datetime.fromtimestamp(ts)
    return f"{dt.strftime('%H:%M:%S')}.{dt.microsecond // 1000:03d}"


def _bar(value: float, maximum: float, width: int = BAR_WIDTH) -> str:
    """Map ``value`` (0..``maximum``) onto a ``width``-long block bar."""
    if maximum <= 0 or value <= 0:
        return " " * width
    if value >= maximum:
        return BAR_CHARS[-1] * width
    ratio = (value / maximum) * width * len(BAR_CHARS)
    full, frac = divmod(ratio, len(BAR_CHARS))
    n_full = int(full)
    bars = BAR_CHARS[-1] * n_full
    if n_full < width:
        bars += BAR_CHARS[int(frac)]
    return bars.ljust(width)


def render_stream_table(events: List[PacketEvent]) -> Table:
    """Render the rolling stream buffer (newest events first)."""
    table = Table(
        header_style="bold cyan",
        expand=True,
        box=None,
    )
    table.add_column("Time", justify="right", no_wrap=True)
    table.add_column("Source", style="bold", no_wrap=True)
    table.add_column("Destination", style="bold", no_wrap=True)
    table.add_column("Proto", justify="center", no_wrap=True)
    table.add_column("Ports", justify="center", no_wrap=True)
    table.add_column("Size", justify="right", no_wrap=True)
    table.add_column("Service", no_wrap=True)
    for event in reversed(events):
        ports = (
            f"{event.sport}→{event.dport}"
            if event.sport or event.dport
            else "—"
        )
        table.add_row(
            _fmt_time(event.timestamp),
            event.src or "?",
            event.dst or "?",
            event.proto,
            ports,
            str(event.size),
            event.service or "",
        )
    return table


def render_top_talkers(
    talkers: Dict[str, Dict],
    top_n: int = DEFAULT_TOP_TALKERS,
    metric: str = "bytes",
) -> Table:
    """Render the busiest hosts with ASCII block activity bars.

    ``talkers`` is the deep copy returned by ``StateStore.snapshot_talkers``.
    """
    table = Table(
        title=f"Top {top_n} Talkers ({metric})",
        header_style="bold yellow",
        expand=True,
        box=None,
    )
    table.add_column("Host", style="bold", no_wrap=True)
    table.add_column("Packets", justify="right")
    table.add_column("Bytes", justify="right")
    table.add_column("Activity", justify="left")

    ranked = sorted(
        talkers.items(),
        key=lambda item: item[1].get(metric, 0),
        reverse=True,
    )[:top_n]
    maximum = max((stats.get(metric, 0) for _, stats in ranked), default=0)
    for ip, stats in ranked:
        table.add_row(
            ip,
            f"{stats.get('pkts', 0):,}",
            f"{stats.get('bytes', 0):,}",
            _bar(stats.get(metric, 0), maximum),
        )
    if not ranked:
        table.add_row("—", "0", "0", " " * BAR_WIDTH)
    return table


def render_telemetry(telemetry: Dict) -> Table:
    """Render the telemetry snapshot (velocity, protocol mix, counters)."""
    table = Table(
        header_style="bold magenta",
        expand=True,
        box=None,
    )
    table.add_column("Metric")
    table.add_column("Value", justify="right")

    mix = telemetry.get("protocol_mix", {}) or {}
    mix_text = ", ".join(
        f"{proto} {pct}%" for proto, pct in sorted(mix.items()) if pct
    )
    rows = [
        ("Packets/sec", f"{telemetry.get('packets_per_sec', 0.0):,.1f}"),
        ("Bytes/sec", f"{telemetry.get('bytes_per_sec', 0.0):,.1f}"),
        ("Avg packet size", f"{telemetry.get('avg_packet_size', 0.0):.1f} B"),
        ("Protocol mix", mix_text or "—"),
        ("Unique hosts", f"{telemetry.get('unique_hosts', 0):,}"),
        ("Total packets", f"{telemetry.get('total_packets', 0):,}"),
        ("Total bytes", f"{telemetry.get('total_bytes', 0):,}"),
        ("Dropped", f"{telemetry.get('dropped_packets', 0):,}"),
        ("Alerts", f"{telemetry.get('alerts_total', 0):,}"),
    ]
    for metric, value in rows:
        table.add_row(metric, value)
    return table


def render_alerts(alerts: List[AlertEvent]) -> Table:
    """Render the alert buffer, colour-mapped by severity."""
    table = Table(
        header_style="bold red",
        expand=True,
        box=None,
    )
    table.add_column("Time", justify="right", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Kind", no_wrap=True)
    table.add_column("Summary")
    for alert in reversed(alerts):
        table.add_row(
            _fmt_time(alert.time),
            Text(alert.severity, style=SEVERITY_STYLES.get(alert.severity, "white")),
            alert.kind,
            alert.summary,
        )
    return table
