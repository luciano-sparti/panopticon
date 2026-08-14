# Panopticon

> A terminal real-time network traffic analyzer and lightweight network intrusion detection system (NIDS) built in Python using Scapy and Rich.

⚠️ **Authorized-Use & Legal Notice**: Only capture traffic on networks and systems you own or have explicit written permission to monitor. Unauthorized packet inspection may violate local and federal laws (such as wiretapping and computer misuse statutes). This tool is strictly for educational, research, and authorized defensive security testing purposes.

---

## Current Status

- ✅ **Phase 1, 2 & 3 Complete** — Core capture sniffer (`Scapy`), metadata parser, thread-safe `StateStore`, streaming PCAP & CSV exporters, pipeline worker, CLI entry point, and threat detection engine (SYN-scan, plaintext, and high-port heuristics) implemented with **107 unit/integration tests passing**.
- ⏳ **Phase 4 & Phase 5 Pending** — Rich terminal interactive UI dashboard (Phase 4), and rule configuration & advanced threat analytics (Phase 5).

---

## Features

- **Live Asynchronous Packet Capture**: Employs Scapy's `AsyncSniffer` in a dedicated background thread with non-blocking queueing to prevent packet drops during high throughput.
- **Protocol & Metadata Parsing**: Extracts timestamp, source/destination IPs, layer 4 protocols (TCP/UDP/ICMP), service ports, and packet lengths into normalized `PacketEvent` structures.
- **State Tracking & Telemetry**: Maintains rolling traffic metrics, protocol distribution percentages, top talker IP statistics, and dropped frame counts via `StateStore`.
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

Launch Panopticon with elevated privileges (`sudo` on Linux/macOS or Administrator prompt on Windows):

```bash
sudo python -m panopticon.analyzer [options]
```

### Command-Line Flags

| Flag | Short | Description | Default |
|---|---|---|---|
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

### Usage Examples

- **Capture on auto-detected default interface**:
  ```bash
  sudo python -m panopticon.analyzer
  ```

- **Sniff specific interface (`eth0`) filtering for HTTP/HTTPS**:
  ```bash
  sudo python -m panopticon.analyzer -i eth0 --filter "tcp port 80 or tcp port 443"
  ```

- **Specify custom export files**:
  ```bash
  sudo python -m panopticon.analyzer --export-pcap capture.pcap --export-csv flows.csv
  ```

- **Stopping Capture**:
  Press **`CTRL-C`** to trigger graceful shutdown. Panopticon closes the sniffer socket, drains remaining queue items through the pipeline, flushes exporters to disk, and prints summary telemetry (including any detector alerts).

---

## License

Distributed under the MIT License. Strictly for authorized security analysis and educational monitoring.
