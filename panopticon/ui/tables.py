"""StateStore snapshot -> Rich renderable renderers.

Every renderer takes a copy-on-write snapshot from ``StateStore.snapshot_*``
and returns a ``rich`` renderable (a ``Table``). Renderers never touch the
store or its mutation API and never block on pipeline state, so they are
safe to call from the UI refresh thread at any cadence.
"""

from __future__ import annotations

import datetime

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

# Severity ranking used by the alert filter (None = show everything).
_SEVERITY_LEVEL = {"info": 0, "warn": 1, "critical": 2}


def _fmt_bytes(n: float) -> str:
    """Human-readable byte count (IEC units, 1 decimal below GiB)."""
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024.0 or unit == "TiB":
            if unit == "B":
                return f"{int(n):,} {unit}"
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TiB"


def _fmt_time(ts: float) -> str:
    """Format an epoch timestamp as HH:MM:SS.mmm."""
    # Deliberately renders the operator's local wall-clock time.
    dt = datetime.datetime.fromtimestamp(ts)  # noqa: DTZ006
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


def _spark_char(value: float, maximum: float) -> str:
    """Map one sparkline sample onto ``BAR_CHARS``; blank for empty/slack bins."""
    if not (maximum and value):
        return " "
    return BAR_CHARS[min(len(BAR_CHARS) - 1, int(value / maximum * (len(BAR_CHARS) - 1)))]


def render_stream_table(
    events: list[PacketEvent],
    self_ips: set[str] | None = None,
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
        ports = f"{event.sport}→{event.dport}" if event.sport or event.dport else "—"
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
        row.extend(
            [
                event.src or "?",
                event.dst or "?",
                event.proto,
                ports,
                str(event.size),
                event.service or "",
            ]
        )
        table.add_row(*row)
    return table


def rank_talkers(talkers: dict[str, dict], metric: str = "bytes") -> list:
    """Order ``(ip, stats)`` pairs: pinned talkers first, then metric desc.

    Shared by the renderer and the selector/key handler so both operate on
    the exact same ordering.
    """

    def sort_key(item):
        _ip, stats = item
        tags = stats.get("tags", ()) or ()
        pinned = 0 if "pinned" in tags else 1
        return (pinned, -stats.get(metric, 0))

    return sorted(talkers.items(), key=sort_key)


def render_top_talkers(
    talkers: dict[str, dict],
    top_n: int = DEFAULT_TOP_TALKERS,
    metric: str = "bytes",
    selected: str | None = None,
    rates: dict[str, float] | None = None,
    bar_peak: float | None = None,
) -> Table:
    """Render the busiest hosts with ASCII block activity bars.

    ``talkers`` is the (shallow) copy returned by ``StateStore.snapshot_talkers``.
    Pinned talkers sort to the top (with a mini-telemetry caption) and the
    currently selected host is highlighted. ``rates`` maps ip -> bytes/sec
    (computed by the Dashboard between refresh ticks); ``bar_peak`` overrides
    the bar scaling maximum (a decaying peak keeps bars comparable over time).
    """
    table = Table(
        title=f"Top {top_n} Talkers ({metric})",
        header_style="bold yellow",
        expand=True,
        box=None,
    )
    table.add_column("Host", style="bold", no_wrap=True)
    has_names = False
    ranked = rank_talkers(talkers, metric)[:top_n]
    maximum = (
        bar_peak
        if bar_peak is not None
        else max((stats.get(metric, 0) for _, stats in ranked), default=0)
    )
    if any(stats.get("name") for _, stats in ranked):
        has_names = True
        table.add_column("Name", no_wrap=True)
    table.add_column("Packets", justify="right")
    table.add_column("Bytes", justify="right")
    table.add_column("Rate", justify="right", no_wrap=True)
    table.add_column("Activity", justify="left")
    table.add_column("Tags", no_wrap=True)

    pinned_lines = []
    for ip, stats in ranked:
        tags = stats.get("tags", ()) or ()
        is_sel = ip == selected
        is_pin = "pinned" in tags
        if is_sel and is_pin:
            host = Text(f"▸ ● {ip}", style="bold reverse yellow")
        elif is_sel:
            host = Text(f"▸ {ip}", style="bold reverse yellow")
        elif is_pin:
            host = Text(f"● {ip}", style="bold yellow")
        else:
            host = Text(ip)

        rate = (rates or {}).get(ip, 0.0)
        name = stats.get("name") or ""
        row = [
            host,
            name if has_names else None,
            f"{stats.get('pkts', 0):,}",
            f"{_fmt_bytes(stats.get('bytes', 0))}",
            f"{_fmt_bytes(rate)}/s" if rate >= 1 else "—",
            _bar(stats.get(metric, 0), maximum),
            ", ".join(tags) if tags else "",
        ]
        table.add_row(*[cell for cell in row if cell is not None])
        if is_pin:
            pinned_lines.append(
                f"{ip} — {stats.get('pkts', 0):,} pkts · {_fmt_bytes(stats.get('bytes', 0))}"
            )
    if pinned_lines:
        table.caption = "\n".join(f"Pinned: {line}" for line in pinned_lines)
    if not ranked:
        table.add_row(
            Text("listening… no traffic yet", style="dim"),
            "",
            "",
            "",
            " " * BAR_WIDTH,
            "",
        )
    return table


def render_telemetry(
    telemetry: dict,
    sparkline: list | None = None,
) -> Table:
    """Render the telemetry snapshot (velocity, protocol mix, counters).

    ``sparkline`` is an optional list of ``(pps, bps)`` samples collected by
    the Dashboard between refresh ticks; it renders as two history rows.
    """
    table = Table(
        header_style="bold magenta",
        expand=True,
        box=None,
    )
    table.add_column("Metric")
    table.add_column("Value", justify="right")

    mix = telemetry.get("protocol_mix", {}) or {}
    mix_text = ", ".join(f"{proto.upper()} {pct}%" for proto, pct in sorted(mix.items()) if pct)
    dropped = telemetry.get("dropped_packets", 0)
    dropped_detail = (
        f"{dropped:,} (parse {telemetry.get('parse_failures', 0):,} / "
        f"queue {telemetry.get('queue_drops', 0):,})"
        if dropped
        else f"{dropped:,}"
    )
    rows: list[tuple[str, str | Text]] = [
        ("Packets/sec", f"{telemetry.get('packets_per_sec', 0.0):,.1f}"),
        ("Bytes/sec", f"{_fmt_bytes(telemetry.get('bytes_per_sec', 0.0))}/s"),
        ("Avg packet size", _fmt_bytes(telemetry.get("avg_packet_size", 0.0))),
        ("Protocol mix", mix_text or "—"),
        ("Unique hosts", f"{telemetry.get('unique_hosts', 0):,}"),
        ("Active sessions", f"{telemetry.get('active_sessions', 0):,}"),
        ("Total packets", f"{telemetry.get('total_packets', 0):,}"),
        ("Total bytes", _fmt_bytes(telemetry.get("total_bytes", 0))),
        ("Dropped", dropped_detail),
        ("Alerts", f"{telemetry.get('alerts_total', 0):,}"),
    ]
    if sparkline:
        pps_max = max((p for p, _ in sparkline), default=0.0)
        bps_max = max((b for _, b in sparkline), default=0.0)
        pps_bar = "".join(_spark_char(p, pps_max) for p, _ in sparkline)
        bps_bar = "".join(_spark_char(b, bps_max) for _, b in sparkline)
        rows.append(("pp/s history", Text(pps_bar, style="cyan")))
        rows.append(("B/s history", Text(bps_bar, style="magenta")))
    for metric, value in rows:
        table.add_row(metric, value)
    return table


def render_alerts(
    alerts: list[AlertEvent],
    min_severity: str | None = None,
) -> Table:
    """Render the alert buffer, colour-mapped by severity with dual-coding.

    ``min_severity`` filters: ``"warn"`` shows warn+critical; ``"critical"``
    shows only critical alerts.
    """
    table = Table(
        header_style="bold red",
        expand=True,
        box=None,
    )
    table.add_column("Time", justify="right", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Kind", no_wrap=True)
    table.add_column("Summary")
    floor = _SEVERITY_LEVEL.get(min_severity) if min_severity else None
    shown = 0
    for alert in reversed(alerts):
        sev_key = alert.severity.lower()
        if floor is not None and _SEVERITY_LEVEL.get(sev_key, 0) < floor:
            continue
        badge = SEVERITY_BADGES.get(sev_key, alert.severity)
        style = SEVERITY_STYLES.get(sev_key, "white")
        table.add_row(
            _fmt_time(alert.time),
            Text(badge, style=style),
            alert.kind,
            alert.summary,
        )
        shown += 1
    if not shown:
        placeholder = (
            "no critical alerts" if min_severity == "critical" else "listening… no alerts yet"
        )
        table.add_row(Text("—", style="dim"), "", "", Text(placeholder, style="dim"))
    return table


def render_host_inspector(
    ip: str,
    talker_data: dict | None,
    flow_data: dict | None,
    tags: list[str],
    alerts: list[AlertEvent],
    ports_contacted: list[int] | None = None,
    proto_mix: dict[str, int] | None = None,
    first_seen: float | None = None,
    sessions: list[dict] | None = None,
) -> Table:
    """Render a deep-dive inspection table for a selected host.

    ``ports_contacted`` / ``proto_mix`` / ``first_seen`` / ``sessions`` are
    derived from the store snapshots by the dashboard; all are optional.
    """
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
    if talker_data:
        cls = talker_data.get("class")
        if cls:
            table.add_row("Classification", cls.replace("-", " ").title())
        name = talker_data.get("name")
        if name:
            table.add_row("Hostname", name)
    if first_seen is not None:
        table.add_row("First Seen", _fmt_time(first_seen))
    table.add_row("Total Packets", f"{pkts:,}")
    table.add_row("Total Volume", _fmt_bytes(bytes_val))
    table.add_row("Last Active", last_str)

    if flow_data:
        flow_str = (
            f"local port {flow_data['local_port']} ↔ remote port "
            f"{flow_data['remote_port']} ({flow_data['proto']})"
        )
        table.add_row("Active Flow", flow_str)
    else:
        table.add_row("Active Flow", "no active flow recorded")

    if ports_contacted:
        shown = ports_contacted[-12:]
        more = len(ports_contacted) - len(shown)
        suffix = f" (+{more} more)" if more > 0 else ""
        table.add_row(
            "Ports Contacted",
            ", ".join(str(p) for p in shown) + suffix,
        )
    if proto_mix:
        mix_str = ", ".join(
            f"{proto.upper()} {count:,}"
            for proto, count in sorted(proto_mix.items(), key=lambda kv: -kv[1])
            if count
        )
        table.add_row("Protocol Mix (buffer)", mix_str or "—")

    if sessions:
        lines = [
            f"{s['proto'].upper()} {s['src']}:{s['sport']} → {s['dst']}:{s['dport']} "
            f"[{s['state']}] {s['pkts']:,} pkts"
            for s in sessions[:6]
        ]
        table.add_row(
            f"Sessions ({len(sessions)})",
            "\n".join(lines) if lines else "none",
        )

    host_alerts = [a for a in alerts if a.src == ip or a.dst == ip]
    if host_alerts:
        alert_lines = [f"[{a.severity}] {a.kind}: {a.summary}" for a in host_alerts[-3:]]
        table.add_row("Related Alerts", "\n".join(alert_lines))
    else:
        table.add_row("Related Alerts", "none")

    table.caption = "Press Enter or Esc to return to dashboard"
    return table


def render_help(enable_kill: bool = False) -> Table:
    """The dismissible full-screen key-reference overlay."""
    lines = [
        ("q", "quit"),
        ("↑/↓, j, C-n", "select talker (C-p selects up)"),
        ("Space", "freeze / resume stream"),
        ("m", "toggle sort metric (bytes/pkts)"),
        ("1-4, Tab, 0", "zoom panes / show all"),
        ("Enter", "inspect selected host (Enter/Esc closes)"),
        ("p", "pin / unpin selected host"),
        ("t / T", "add / remove tag on selected host"),
        ("!", "cycle alert severity filter (all → warn+ → critical)"),
        ("Esc", "close overlay · clear selection · cancel prompt"),
    ]
    if enable_kill:
        lines.append(("k, x", "scoped kill of selected host's flow (confirm y/n)"))
    table = Table(
        title="Help — press any key to close",
        header_style="bold cyan",
        expand=True,
        box=None,
    )
    table.add_column("Key", style="bold cyan", no_wrap=True)
    table.add_column("Action")
    for key, action in lines:
        table.add_row(key, action)
    return table
