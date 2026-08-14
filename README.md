# Panopticon — Network Traffic Analyzer & Mini-NIDS Dashboard

A terminal-based, real-time network traffic analyzer and lightweight intrusion detection system (NIDS) built in Python. It captures live packets, renders a live-updating dashboard in the terminal, flags suspicious activity, and exports session data for further forensics in Wireshark.

> ⚠️ **Legal notice:** Only capture traffic on networks and devices you own or have explicit written permission to monitor. Unauthorized packet capture may violate local laws (e.g., wiretapping/computer misuse statutes). This tool is for educational and authorized security-testing use only.

---

## Features

- **Live packet capture** using Scapy's sniffing engine, with per-packet metadata parsing (timestamp, src/dst IP, protocol, service/port, size).
- **Real-time terminal UI** built with [Rich](https://github.com/Textualize/rich) — auto-refreshing tables, panels, and a live layout (no flicker, no manual clearing).
- **Traffic velocity tracking** — packets/sec, average packet size, protocol mix (TCP/UDP/ICMP %).
- **Top talkers panel** — ranks source IPs by packet count and data volume, with a simple ASCII/text volume bar.
- **Anomaly / threat flagging**, including:
  - TCP SYN scan detection (many SYNs, no completed handshake, from one source in a short window)
  - Unencrypted traffic detection (plaintext HTTP, Telnet, FTP control channel, etc.)
  - High/unusual destination port activity
- **Session export** to `.pcap` (via `scapy.wrpcap`) and `.csv` (via the `csv` module) for later analysis in Wireshark or spreadsheets.
- **Keyboard control** — press `q` to gracefully stop capture and exit.

---

## Architecture

```
┌────────────────────┐
│   Sniffer thread    │  scapy.sniff(prn=callback, store=False)
└─────────┬───────────┘
          │ raw packets
          ▼
┌────────────────────┐
│  Packet Parser       │  extract IPs, proto, ports, size, service name
└─────────┬───────────┘
          │ normalized event
          ▼
┌────────────────────┐     ┌──────────────────────┐
│  State Store         │────▶│  Anomaly Detector      │
│ (rolling buffers,     │     │ (SYN-scan, plaintext,  │
│  counters, top-N)     │     │  high-port heuristics) │
└─────────┬───────────┘     └──────────┬────────────┘
          │                              │
          ▼                              ▼
┌─────────────────────────────────────────────┐
│           Rich Live Dashboard (UI thread)      │
│  Packet stream table | Top talkers | Telemetry │
└─────────────────────────────────────────────┘
          │
          ▼
   PCAP / CSV export on exit
```

Capture runs in a background thread (or async loop) so the UI can redraw independently at a fixed interval (e.g., every 0.5–1s) without blocking on packet I/O.

---

## Tech Stack

| Component        | Library                          |
|-------------------|-----------------------------------|
| Packet capture     | `scapy` (`sniff`, `AsyncSniffer`) |
| Terminal UI        | `rich` (`Live`, `Table`, `Panel`, `Layout`) |
| CLI args           | `argparse`                       |
| Data export        | `scapy.utils.wrpcap`, built-in `csv` |
| Threading          | `threading` / `queue` for producer-consumer between sniffer and UI |

---

## Requirements

```
Python 3.9+
scapy>=2.5.0
rich>=13.0.0
```

Packet capture requires elevated privileges:
- **Linux/macOS:** run with `sudo`, or grant the interpreter `CAP_NET_RAW`/`CAP_NET_ADMIN` via `setcap`.
- **Windows:** install [Npcap](https://npcap.com/) first, then run the terminal as Administrator.

---

## Installation

```bash
git clone https://github.com/<your-username>/mini-nids-dashboard.git
cd mini-nids-dashboard
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

`requirements.txt`:
```
scapy
rich
```

---

## Usage

```bash
sudo python analyzer.py --interface eth0
```

Common flags:

| Flag               | Description                                      | Default   |
|---------------------|--------------------------------------------------|-----------|
| `--interface, -i`   | Network interface to sniff on                    | auto-detect |
| `--filter`          | BPF filter (e.g. `"tcp or udp"`)                 | none      |
| `--refresh`         | Dashboard refresh rate (seconds)                 | `0.5`     |
| `--export-pcap`     | Path to write captured packets on exit           | `session.pcap` |
| `--export-csv`      | Path to write flow log on exit                   | `session.csv`  |
| `--syn-threshold`   | SYNs/sec from one source to trigger scan alert   | `20`      |

Press **`q`** at any time to stop capture cleanly and write exports.

---

## Building the Dashboard UI (Rich)

The layout in the screenshot maps roughly to three Rich components:

1. **`Table`** for the live packet stream (Date, Time, Source IP, Destination IP, Protocol, Service, Size) — new rows appended, old rows trimmed to keep it on-screen.
2. **`Table` + `Panel`** side-by-side (via `Layout().split_row`) for:
   - Top Network Generators (source IP, packet count, data volume, bar)
   - Telemetry & Watchlist (velocity, status, unique hosts, protocol mix, flagged high ports)
3. Wrap everything in `rich.live.Live(layout, refresh_per_second=2)` so the whole screen redraws in place.

Minimal skeleton:

```python
from rich.live import Live
from rich.layout import Layout
from rich.table import Table

def build_layout(state) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="stream", ratio=2),
        Layout(name="lower", ratio=1),
    )
    layout["lower"].split_row(Layout(name="top_talkers"), Layout(name="telemetry"))
    layout["stream"].update(render_stream_table(state))
    layout["top_talkers"].update(render_top_talkers(state))
    layout["telemetry"].update(render_telemetry_panel(state))
    return layout

with Live(build_layout(state), refresh_per_second=2, screen=True) as live:
    while running:
        live.update(build_layout(state))
```

---

## Anomaly Detection Logic (simplified)

- **SYN scan:** maintain a rolling window (e.g. last 5s) of `(src_ip, dst_port, flags)`. If a single source sends SYNs to many distinct ports/hosts without matching SYN-ACKs, flag it.
- **Unencrypted traffic:** match on well-known plaintext ports/services (80, 21, 23, unencrypted 25) or inspect payload for cleartext credentials patterns; flag as "unencrypted traffic" in the telemetry panel.
- **High ports:** flag any connection using ephemeral/uncommon high ports (>49152) as informational, not necessarily malicious.

These are heuristics for learning purposes, not production-grade signatures — a real NIDS (Suricata/Snort/Zeek) uses far more rigorous rule sets and statistical baselining.

---

## Project Structure

```
mini-nids-dashboard/
├── analyzer.py          # entry point, CLI, capture loop
├── ui/
│   └── dashboard.py      # Rich layout & rendering
├── detection/
│   └── heuristics.py     # SYN-scan, plaintext, high-port checks
├── export/
│   └── writers.py        # PCAP/CSV export helpers
├── requirements.txt
└── README.md
```

---

## Roadmap Ideas

- GeoIP lookups for source addresses
- Configurable alert rules loaded from YAML
- Web-based dashboard (FastAPI + WebSockets) as an alternative to the terminal UI
- Integration with Suricata rule format for signature-based detection

---

## License

MIT — for educational and authorized security research use only.
