# Panopticon

> A terminal real-time network traffic analyzer and lightweight network intrusion detection system (NIDS) built in Python using Scapy and Rich.

⚠️ **Authorized-Use & Legal Notice**: Only capture traffic on networks and systems you own or have explicit written permission to monitor. Unauthorized packet inspection may violate local and federal laws (such as wiretapping and computer misuse statutes). This tool is strictly for educational, research, and authorized defensive security testing purposes.

---

## Current Status

- ✅ **Phases 1–6 Complete + Enhanced UI/UX** — Core capture sniffer (`Scapy`), metadata parser, thread-safe `StateStore`, streaming PCAP & CSV exporters, pipeline worker, CLI entry point, threat detection engine (SYN-scan, plaintext, and high-port heuristics), alert JSONL exporter (`session.alerts.jsonl`), Rich terminal interactive dashboard with freeze (`Space`), metric toggle (`m`), panel zoom (`1`–`4`), deep-dive Host Inspector (`Enter`), selector/pin/tag/kill, and automatic `self:` tagging — **204 unit/integration tests passing**.


---

## Features

- **Live Asynchronous Packet Capture**: Employs Scapy's `AsyncSniffer` in a dedicated background thread with non-blocking queueing to prevent packet drops during high throughput.
- **Protocol & Metadata Parsing**: Extracts timestamp, source/destination IPs, layer 4 protocols (TCP/UDP/ICMP), service ports, and packet lengths into normalized `PacketEvent` structures.
- **State Tracking & Telemetry**: Maintains rolling traffic metrics, protocol distribution percentages, top talker IP statistics, and dropped frame counts via `StateStore`.
- **IP Tagging**: Tag any talker manually (`t`/`T`) or automatically — the host's own IPs are resolved from the kernel (`/proc`/sysfs) at startup and any packet touching an owned IP gets a `self:<hostname>` tag (loopback gets `self:localhost`). Tags survive talker eviction and can be persisted with `--tags-file`.
- **Interactive Dashboard**: A persistent key-legend footer drives a non-blocking selector (↑/↓), pin-to-top (`p`), inline tag prompts (`t`/`T`), scoped kill (`k`, behind `--enable-kill`), and help (`?`).
- **Dual Streaming Exporters**: Concurrently writes raw frames to `.pcap` (via Scapy `PcapWriter`, append mode, linktype auto-inferred from the first frame) and flow statistics to `.csv` (append mode, header written once) for forensic analysis in Wireshark or analytical tools.
- **Clean Pipeline & Shutdown**: Signal-aware worker pipeline (handling `SIGINT`/`SIGTERM` / `CTRL-C`) that gracefully drains in-flight capture queues and flushes disk buffers on exit. The detector engine raises `syn_scan`, `plaintext`, and `high_port` alerts, which are summarized in the shutdown telemetry.

---

## Architecture

```
┌────────────────────────┐
│  Scapy AsyncSniffer    │  (Capture thread, store=False)
└───────────┬────────────┘
            │ raw frames
            ▼
┌────────────────────────┐
│  Packet Parser         │  (Extract IPs, protocols, ports, payload size)
└───────────┬────────────┘
            │ PacketEvent
            ▼
┌────────────────────────┐
│  Bounded Thread Queue  │  (Non-blocking queueing)
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐      ┌────────────────────────┐
│  Pipeline Worker       │ ────▶│  State Store           │  (Telemetry & Top Talkers)
└───────────┬────────────┘      └────────────────────────┘
            │
            ├───────────────────▶ Detector Engine (SYN-scan, plaintext, high-port)
            │
            ▼
┌────────────────────────┐
│  Exporters (PCAP/CSV)  │ ────▶ session.pcap & session.csv
└────────────────────────┘
```

---

## Prerequisites & Requirements

- **Python**: `3.9+`
- **Dependencies**: `scapy>=2.5.0`, `rich>=13.0.0`, `pytest>=7.0.0`
- **Elevated Privileges**: Raw socket sniffing requires administrator privileges:
  - **Linux / macOS**: Run with `sudo` or assign raw network capabilities (`sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)`).
  - **Windows**: Install [Npcap](https://npcap.com/) (with WinPcap API compatibility enabled) and run shell as Administrator.

---

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/luciano-sparti/panopticon.git
   cd panopticon
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate    # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run tests**:
   ```bash
   pytest
   ```

---

## Usage

Launch Panopticon with elevated privileges. **Important:** `sudo` resets `PATH`, so after `source .venv/bin/activate` you must run the venv interpreter explicitly — do **not** use bare `sudo python` (it would use the system Python without scapy). Either:

```bash
# option A — explicit venv python under sudo
source .venv/bin/activate
sudo "$VIRTUAL_ENV/bin/python" -m panopticon.analyzer [options]
```

```bash
# option B — grant CAP_NET_RAW once, then run without sudo
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$VIRTUAL_ENV/bin/python")"
"$VIRTUAL_ENV/bin/python" -m panopticon.analyzer [options]
```

### Command-Line Flags

| Flag | Short | Description | Default |
|---|---|---|---|
| `--version` | | Print the version and exit | |
| `--interface` | `-i` | Network interface to sniff on | Auto-detected |
| `--filter` | | BPF (Berkeley Packet Filter) string (e.g. `"tcp or udp"`) | None |
| `--export-pcap` | | Output path for raw captured packets | `session.pcap` |
| `--export-csv` | | Output path for CSV flow log | `session.csv` |
| `--refresh` | | State maintenance loop interval in seconds | `0.5` |
| `--queue-size` | | Capture queue depth before dropping frames | `10000` |
| `--syn-threshold` | | Distinct unresponded SYN targets that trigger a scan alert | `20` |
| `--syn-window` | | Sliding window (s) for SYN-scan counting | `5.0` |
| `--high-port` | | Destination ports at or above this value raise high-port alerts | `49152` |
| `--alert-cooldown` | | Min seconds between accepted alerts of the same kind/source | `30.0` |
| `--no-ui` | | Disable the dashboard and keyboard watcher (headless/CI) | Off |
| `--enable-kill` | | Enable the scoped `k` kill (SIGTERM of the flow's local process, after y/n confirm) | Off |
| `--tags-file` | | JSON `{ip: [tags]}` path loaded at start and saved on exit | None |

### Interactive Keys

| Key | Action |
|---|---|
| `q` / `Ctrl+C` | Quit |
| `↑` / `↓` (or `j`) | Move the selection across top-talkers |
| `Space` | Freeze / unfreeze live packet stream display |
| `m` | Toggle top-talker sorting metric (**Bytes** $\leftrightarrow$ **Packets**) |
| `1`–`4` / `Tab` | Focus / zoom into **1** (Stream), **2** (Talkers), **3** (Alerts), or **4** (Telemetry); `0`/`Tab` restores all 4 panes |
| `Enter` | Open / close deep-dive **Host Inspector** modal for the selected talker |
| `p` | Pin/unpin the selected talker (kept at the top of the talkers list) |
| `t` | Inline prompt to add a tag to the selected talker |
| `T` | Inline prompt to remove a tag from the selected talker |
| `k` / `K` / `x` | Kill the local process owning the selected talker's flow (needs `--enable-kill`, then confirm `y`/`n`) |
| `?` | Show the key legend in the footer |


### Usage Examples

- **Capture on auto-detected default interface**:
  ```bash
  sudo "$VIRTUAL_ENV/bin/python" -m panopticon.analyzer
  ```

- **Sniff specific interface (`eth0`) filtering for HTTP/HTTPS**:
  ```bash
  sudo "$VIRTUAL_ENV/bin/python" -m panopticon.analyzer -i eth0 --filter "tcp port 80 or tcp port 443"
  ```

- **Specify custom export files**:
  ```bash
  sudo "$VIRTUAL_ENV/bin/python" -m panopticon.analyzer --export-pcap capture.pcap --export-csv flows.csv
  ```

- **Stopping Capture**:
  Press **`CTRL-C`** (or `q`) to trigger graceful shutdown. Panopticon closes the sniffer socket, drains remaining queue items through the pipeline, flushes exporters to disk, saves the tags file (if `--tags-file` given), and prints summary telemetry (including any detector alerts).

### Usage Examples

- **Check the version**:
  ```bash
  "$VIRTUAL_ENV/bin/python" -m panopticon.analyzer --version
  ```

- **Persist manual tags across sessions**:
  ```bash
  sudo "$VIRTUAL_ENV/bin/python" -m panopticon.analyzer --tags-file tags.json
  ```

- **Enable the scoped kill key**:
  ```bash
  sudo "$VIRTUAL_ENV/bin/python" -m panopticon.analyzer --enable-kill
  ```
  Selecting a talker and pressing `k` resolves the local process owning that
  flow (via `/proc`) and asks for a `y`/`n` confirmation before sending
  `SIGTERM`. Kill is always disabled by default and never auto-kills.

---

## License

Distributed under the MIT License. Strictly for authorized security analysis and educational monitoring.
