"""StateStore snapshot -> Rich renderable renderers.

Every renderer takes a deep-copied snapshot from ``StateStore.snapshot_*``
and returns a ``rich`` renderable (a ``Table``). Renderers never touch the
store or its mutation API and never block on pipeline state, so they are
safe to call from the UI refresh thread at any cadence.
"""

from __future__ import annotations

import datetime
from typing import Dict, List, Optional

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

# Dual-coding text badges for colorblind accessibility.
SEVERITY_BADGES = {
    "info": "ℹ info",
    "warn": "⚠ warn",
    "critical": "⛔ crit",
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


def render_stream_table(
    events: List[PacketEvent],
    self_ips: Optional[Set[str]] = None,
) -> Table:
    """Render the rolling stream buffer (newest events first)."""
    table = Table(
        header_style="bold cyan",
        expand=True,
        box=None,
    )
    table.add_column("Time", justify="right", no_wrap=True)
    if self_ips:
        table.add_column("Dir", justify="center", no_wrap=True)
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
        row = [_fmt_time(event.timestamp)]
        if self_ips:
            if event.src in self_ips and event.dst in self_ips:
                direction = "↔"
            elif event.src in self_ips:
                direction = "▲"
            elif event.dst in self_ips:
                direction = "▼"
            else:
                direction = "·"
            row.append(direction)
        row.extend([
            event.src or "?",
            event.dst or "?",
            event.proto,
            ports,
            str(event.size),
            event.service or "",
        ])
        table.add_row(*row)
    return table


def rank_talkers(talkers: Dict[str, Dict], metric: str = "bytes") -> List:
    """Order ``(ip, stats)`` pairs: pinned talkers first, then metric desc.

    Shared by the renderer and the selector/key handler so both operate on
    the exact same ordering.
    """
    def sort_key(item):
        ip, stats = item
        tags = stats.get("tags", ()) or ()
        pinned = 0 if "pinned" in tags else 1
        return (pinned, -stats.get(metric, 0))

    return sorted(talkers.items(), key=sort_key)


def render_top_talkers(
    talkers: Dict[str, Dict],
    top_n: int = DEFAULT_TOP_TALKERS,
    metric: str = "bytes",
    selected: Optional[str] = None,
) -> Table:
    """Render the busiest hosts with ASCII block activity bars.

    ``talkers`` is the deep copy returned by ``StateStore.snapshot_talkers``.
    Pinned talkers sort to the top (with a mini-telemetry caption) and the
    currently selected host is highlighted.
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
    table.add_column("Tags", no_wrap=True)

    ranked = rank_talkers(talkers, metric)[:top_n]
    maximum = max((stats.get(metric, 0) for _, stats in ranked), default=0)
    pinned_lines = []
    for ip, stats in ranked:
        tags = stats.get("tags", ()) or ()
        is_sel = (ip == selected)
        is_pin = "pinned" in tags
        if is_sel and is_pin:
            host = Text(f"▸ ● {ip}", style="bold reverse yellow")
        elif is_sel:
            host = Text(f"▸ {ip}", style="bold reverse yellow")
        elif is_pin:
            host = Text(f"● {ip}", style="bold yellow")
        else:
            host = Text(ip)

        table.add_row(
            host,
            f"{stats.get('pkts', 0):,}",
            f"{stats.get('bytes', 0):,}",
            _bar(stats.get(metric, 0), maximum),
            ", ".join(tags) if tags else "",
        )
        if is_pin:
            pinned_lines.append(
                f"{ip} — {stats.get('pkts', 0):,} pkts · {stats.get('bytes', 0):,} B"
            )
    if pinned_lines:
        table.caption = "\n".join(f"Pinned: {line}" for line in pinned_lines)
    if not ranked:
        table.add_row("—", "0", "0", " " * BAR_WIDTH, "")
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
        f"{proto.upper()} {pct}%" for proto, pct in sorted(mix.items()) if pct
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
    """Render the alert buffer, colour-mapped by severity with dual-coding."""
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
        sev_key = alert.severity.lower()
        badge = SEVERITY_BADGES.get(sev_key, alert.severity)
        style = SEVERITY_STYLES.get(sev_key, "white")
        table.add_row(
            _fmt_time(alert.time),
            Text(badge, style=style),
            alert.kind,
            alert.summary,
        )
    return table


def render_host_inspector(
    ip: str,
    talker_data: Optional[Dict],
    flow_data: Optional[Dict],
    tags: List[str],
    alerts: List[AlertEvent],
) -> Table:
    """Render a deep-dive inspection table for a selected host."""
    table = Table(
        title=f"Host Inspection: {ip}",
        header_style="bold cyan",
        expand=True,
        box=None,
    )
    table.add_column("Property", style="bold", no_wrap=True)
    table.add_column("Value")

    tag_str = ", ".join(tags) if tags else "none"
    pkts = talker_data.get("pkts", 0) if talker_data else 0
    bytes_val = talker_data.get("bytes", 0) if talker_data else 0
    last_seen = talker_data.get("last_seen", 0.0) if talker_data else 0.0
    last_str = _fmt_time(last_seen) if last_seen else "unknown"

    table.add_row("Host IP", ip)
    table.add_row("Tags", tag_str)
    table.add_row("Total Packets", f"{pkts:,}")
    table.add_row("Total Volume", f"{bytes_val:,} bytes")
    table.add_row("Last Active", last_str)

    if flow_data:
        flow_str = f"local port {flow_data['local_port']} ↔ remote port {flow_data['remote_port']} ({flow_data['proto']})"
        table.add_row("Active Flow", flow_str)
    else:
        table.add_row("Active Flow", "no active flow recorded")

    host_alerts = [a for a in alerts if a.src == ip or a.dst == ip]
    if host_alerts:
        alert_lines = [f"[{a.severity}] {a.kind}: {a.summary}" for a in host_alerts[-3:]]
        table.add_row("Related Alerts", "\n".join(alert_lines))
    else:
        table.add_row("Related Alerts", "none")

    table.caption = "Press Enter or Esc to return to dashboard"
    return table

