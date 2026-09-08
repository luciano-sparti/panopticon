# Panopticon — Improvement Plan

Findings from the full-codebase review (post-Phase 6), ordered by impact.
Each item cites the affected module. Phases are sequenced so correctness and
safety-net work lands before performance and feature work.

## Phase 7 — Correctness fixes + safety net

- [x] **7.1 Alert loss in JSONL export** (`detection/base.py`, `pipeline.py`)
  `DetectorEngine.process_event` returned only the *first* alert per packet;
  `pipeline._process` persisted just that one. A packet triggering both
  `plaintext` + `high_port` lost the second alert from `session.alerts.jsonl`.
  **Done:** engine now returns a list of accepted alerts; pipeline writes all
  of them. Regression tests added (engine + pipeline).

- [x] **7.2 PCAP append corruption** (`export/pcap_writer.py`) — **FALSE POSITIVE**
  Verified empirically: scapy's `RawPcapWriter._write_header` already guards
  append mode (re-reads the file, skips if ≥16 bytes present). Appended
  captures read back cleanly; no change made.

- [x] **7.3 Unguarded I/O at startup/shutdown** (`export/alert_writer.py`,
  `analyzer.py`)
  - `AlertExportWriter.__init__` opened bare → unwritable path yielded a
    traceback instead of exit code 2.
    **Done:** construction moved inside the guarded export-file block.
  - `exporter.close()` unguarded in shutdown: an OSError skipped the summary
    print and `_save_tags`. **Done:** each close guarded individually.
  - `drained` was defined inside `finally`; an earlier failure made the
    shutdown summary raise a secondary `NameError`. **Done:** initialized
    before `try:`. Also removed dead `if is_new: pass` block + unused import
    in alert_writer.py.

- [x] **7.4 Latent NameErrors masked by lazy annotations**
  - `core/procs.py`: `Optional` used but not imported. **Fixed.**
  - `ui/tables.py`: `Set` used but not imported. **Fixed.**
  Verified via `typing.get_type_hints` on both signatures.

- [x] **7.5 CI + lint/type-check config** (`.github/workflows/ci.yml`,
  `pyproject.toml`) — pytest matrix (3.9/3.11/3.13), ruff (lint + format),
  mypy so regressions like 7.4 cannot land silently. **Done:** CI workflow
  added; ruff and mypy wired into pyproject (dev extras + config); the
  codebase was ruff-formatted and all 259 lint findings fixed; all 24 mypy
  findings fixed. Verifying CI locally also exposed a latent real bug:
  `PipelineWorker._stop = threading.Event()` shadowed `Thread._stop`, so a
  worker still running at `join()` crashed with "'Event' object is not
  callable" (renamed to `_stop_event`).

## Phase 8 — Performance

- [x] **8.1** Stop double dissection: carry payload bytes on `PacketEvent`
  once in `core/parser.py`; drop `PlaintextDetector` re-parse of raw bytes
  (`detection/plaintext.py:_dissect`). Biggest CPU win.
- [x] **8.2** Replace `copy.deepcopy` snapshots with shallow copies
  (`core/store.py` snapshot methods; frozen dataclasses only).
- [x] **8.3** Extract shared bounded-LRU utility; replace triplicated O(n)
  eviction scans (`store.py`, `syn_scan.py`, `high_port.py`).
- [x] **8.4** Smooth EWMA: accumulate counts, update once per refresh tick
  instead of per-packet `1/dt` (`core/store.py`).
- [x] **8.5** PCAP fidelity: write `pkt.original` wire bytes instead of
  re-serialized `bytes(pkt)` (`capture/sniffer.py`).

## Phase 9 — Robustness & features

- [ ] **9.1** Split dropped-packet counters: parse failures vs queue-full
  backpressure (`capture/sniffer.py`).
- [ ] **9.2** Validate BPF filter up front; fail fast instead of async poll.
- [ ] **9.3** Join the real sniffer thread (`AsyncSniffer.thread`); wrapper
  thread joins a dead thread today.
- [ ] **9.4** Restore TTY state via `finally`/`atexit` in `KeyboardWatcher`.
- [ ] **9.5** Inject a Clock abstraction (monotonic housekeeping vs packet
  time for detection windows) — NTP steps / pcap replays break TTLs today.
- [ ] **9.6** Reverse DNS (cached, opt-in) + private/link-local/multicast
  classification for inspector/talkers tables.
- [ ] **9.7** TLS SNI / DHCP hostname extraction in parser → meaningful names.
- [ ] **9.8** Flow/session tracking → FIN/NULL/Xmas scan detection.
- [ ] **9.9** New detectors: beaconing, bandwidth-abuse, port-knock.
- [ ] **9.10** Config file (TOML) to replace nine hardcoded CLI flags.

## Phase 9b — UI/UX improvements

Batch A — quick wins:
- [x] **A1 Thread-safety** (`ui/keys.py`): **Done** — `UIControls` guarded by
  an `RLock` (`feed`, `footer_text`, `prompt_text`, `_set_status`).
- [x] **A2 Prompt UX** (`ui/keys.py`): **Done** — backspace on empty buffer
  cancels prompt; Ctrl+U clears buffer.
- [x] **A3 Vi-key consistency**: **Done** — Ctrl+P/Ctrl+N select up/down;
  documented in the help overlay.
- [x] **A4 Empty states** (`ui/tables.py`): **Done** — dim placeholder rows
  ("listening… no traffic yet" / "listening… no alerts yet").
- [x] **A5 Wire direction column**: **Done** — dashboard passes
  `store.self_ips()` to `render_stream_table`; ▲/▼/↔ markers now render.
  Bonus: lone-Esc chunks are flushed as Esc keypresses (was pending forever);
  Esc now closes overlays / clears selection.

Batch B — visibility & readability:
- [x] **B1 Help overlay**: **Done** — `?` toggles a persistent overlay
  (`render_help`); any key dismisses it; keys don't act underneath.
- [x] **B2 Mode badges**: **Done** — view-mode name shown persistently in the
  header; stream pane keeps its LIVE/PAUSED title badge.
- [x] **B3 Capture context header**: **Done** — header line with iface, BPF
  filter, view mode, uptime, LIVE/FROZEN state (`render_header`); wired from
  analyzer via `build_dashboard(capture_info=...)`.
- [x] **B4 Humanized units + rates**: **Done** — IEC units everywhere
  (`_fmt_bytes`); per-talker Rate column derived by the Dashboard from
  snapshot diffs between refresh ticks.

Batch C — depth & interactivity:
- [x] **C1 Bar normalization**: **Done** — bars scale against a decaying peak
  (5%/tick) held by the Dashboard instead of the instantaneous max.
- [x] **C2 Telemetry sparkline**: **Done** — rolling 60-sample pp/s and B/s
  history rows in the telemetry pane.
- [x] **C3 Alert pane interactivity**: **Done** — `!` cycles severity filter
  (all → warn+ → critical); title shows live critical/total counts and active
  filter. *(Deferred: terminal bell on critical — writing `\a` from the
  keyboard thread would corrupt the alternate screen; needs coordinated
  console bell.)*
- [x] **C4 Inspector depth**: **Done** — First Seen, Ports Contacted,
  Protocol Mix (all derived from the stream buffer); inside inspection only
  Enter/Esc exit (arrows no longer dismiss).

## Phase 10 — Hygiene (can interleave)

- [ ] Remove dead code: `StateStore.update_many`, `payload_gate` flag,
  unused `self_ips` direction column, `if is_new: pass` in alert_writer.
- [ ] Packaging: exclude tests from wheel, dynamic version, LICENSE file,
  pin/constrain deps, move pytest out of runtime requirements,
  gitignore `session.alerts.jsonl`, remove committed artifacts.
