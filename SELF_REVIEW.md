# Panopticon Self-Review

Rigorous review of the shipped implementation (Phases 1–3, HEAD `7ed8277`).
Baseline: 82 unit/integration tests pass. No code was changed during this review.

Findings are categorized and cite `file:line`. Each is labeled
**real bug** / **robustness gap** / **test gap** with a one-line fix.

---

## Correctness

1. **real bug — high-port threshold is off-by-one vs. the stated requirement.**
   `detection/high_port.py:54` (`if event.dport < self._threshold: return None`)
   alerts on `dport >= 49152`, but the Phase 3 requirement says "dport > 49152".
   Reproduced: `dport=49152` fires. The CLI help (`analyzer.py:87`, "at/above")
   agrees with the code, so only the requirement text disagrees — pick one.
   Fix: `if event.dport <= self._threshold: return None` if strict-greater is intended
   (and align the CLI help text).

2. **real bug — `Sniffer.running` is a broken liveness probe.**
   `capture/sniffer.py:187-189` returns `self._thread.is_alive()`, but the wrapper
   thread runs `target=self._sniffer.start` (`sniffer.py:177-181`) and exits as soon
   as `AsyncSniffer.start()` spawns its own internal thread. Reproduced: `running`
   is `False` while `self._sniffer.running` is `True`. Any monitoring consumer reads
   garbage.
   Fix: `return bool(self._sniffer.running)`.

3. **real bug — capture can die silently and the CLI never notices.**
   If the socket cannot open (bad BPF filter, permission change, interface removed),
   scapy's `_run_catch` swallows the exception into `self.exception` and leaves
   `AsyncSniffer.running` stuck `True`; the wrapper thread exits. The analyzer loop
   (`analyzer.py:156-160`) checks nothing, so it prints "capturing on X" and exports
   zero packets until Ctrl+C. Reproduced non-root: `async_exception=PermissionError`.
   Fix: in the loop, break with a stderr message when `not sniffer.running` or
   `sniffer._sniffer.exception is not None`.

## Security / Safety

4. **robustness gap — cleartext credential scan only covers ~200 payload bytes.**
   `detection/plaintext.py:94-101` scans `raw[:256]`, which includes L2/L3/L4 headers
   (~54 B), so real credentials later in a request body or in later segments are never
   seen; conversely base64/binary payloads can coincidentally contain `USER `/`PASS `
   and false-positive a `warn`. Fix: strip headers before scanning (or raise
   `max_scan_bytes` and scan payload bytes only).

5. **real bug — port-tier summary can name the wrong port.**
   `detection/plaintext.py:59-66`: when the plaintext service is on the *source* side
   (`sport=21`), `port = event.dport or event.sport` prints the unrelated ephemeral
   destination ("unencrypted ftp traffic on port 54321"), and the tier flags
   encrypted-over-plaintext-port traffic (SSH/TLS on 80) as "warn".
   Fix: report the matching port (`event.sport` if it is the plaintext one) and note
   the direction.

6. **robustness gap — alerts are invisible in the shipped CLI.**
   Detection is wired (`analyzer.py:120-131`) but the CLI prints no alerts — only
   packet/drop counts at shutdown (`analyzer.py:174-179`). The NIDS feature is
   effectively silent without the Phase 4 UI. Fix: at minimum print the alert buffer
   (and `alerts_total`) in the shutdown telemetry.

## Robustness

7. **real bug — shutdown drain can run concurrently with the worker.**
   `analyzer.py:163-172`: `worker.stop(); worker.join(timeout=5)` followed by
   `worker.drain()`/`worker.flush()`/`exporter.close()` in the main thread. If the
   worker outlives the 5 s join (stuck on exporter I/O), `_process` runs on two
   threads; `syn_scan._pending` / `high_port._last_alert` and the PcapWriter/CsvWriter
   handles are unlocked → potential dict corruption or interleaved pcap bytes.
   Fix: `worker.join()` without a timeout before `drain()`, or serialize `_process`.

8. **robustness gap — one bad frame stops capture.**
   `capture/sniffer.py:144-148` runs `parse(pkt)`/`bytes(pkt)` unguarded; the parser
   only guards `AttributeError`/`IndexError` (`core/parser.py:48-52,61-65,78-90`). Any
   other exception is caught by scapy's loop handler, which closes the socket and ends
   capture — with the analyzer unaware (see #3).
   Fix: wrap `handle_packet` in try/except and count the frame as dropped.

9. **robustness gap — pipeline thread dies silently on exporter/detector errors.**
   `pipeline.py:96-101` has no try/except; a disk-full/OSError in `exporter.write`
   kills the daemon worker with a stderr traceback while the CLI keeps "running" and
   the queue fills → drops.
   Fix: catch in `run()`, record the error, and surface it in the analyzer loop.

10. **robustness gap — forced `DLT_EN10MB` linktype.**
    `export/pcap_writer.py:35` writes every frame as Ethernet. Non-Ethernet captures
    (`-i lo0` on macOS → LINKTYPE_NULL, raw tunnel links) produce misparsed pcap, and
    scapy can raise on a linktype mismatch → kills the pipeline (see #9).
    Fix: let scapy infer the linktype (drop the override) or map per interface.

11. **robustness gap — CSV truncates, PCAP appends.**
    `export/csv_writer.py:37` opens `"w"`; `export/pcap_writer.py:35` uses
    `append=True`. Two consecutive runs yield a fresh CSV but a pcap from both sessions.
    Fix: pick one semantics for both and document it.

12. **robustness gap — startup errors are raw tracebacks.**
    Exporter construction (`analyzer.py:116-119`) is outside any try/except; an
    unwritable `--export-pcap`/`--export-csv` path raises an uncaught traceback
    instead of a clean exit-2 message like `preflight` produces.
    Fix: wrap startup in try/except → stderr message + return 2.

13. **robustness gap — `auto_detect_interface` misses common virtual devices.**
    `capture/sniffer.py:30-40` excludes docker/veth/virbr/br-/nflog/nfqueue/bt/tap/tun
    but not `utun*`, `vmnet*`, `vboxnet*`, `ppp*`, `wg*` — can auto-pick a dead VPN
    tunnel.
    Fix: extend `_PSEUDO_PREFIXES`.

14. **robustness gap — EWMA velocity freezes on same-timestamp bursts.**
    `core/store.py:159` (`if dt > 0`) means packets sharing a timestamp (libpcap
    microsecond granularity, replayed traces) update only `avg_size`, never pps/bps —
    metrics go stale under bursts. Not a crash (guarded), but the guard is untested.
    Fix: clamp `dt` to a minimum epsilon instead of skipping.

15. **robustness gap — mixed time bases for cooldowns/TTLs.**
    `detection/base.py:93` keys dedup on `event.timestamp`, but `prune()` uses wall
    clock (`base.py:112`); same for `store.prune()` (`store.py:107`) vs `last_seen`
    timestamps. Consistent in live capture, but synthetic/replayed feeds silently
    purge all state. Fix: derive a single clock and pass it through.

## Test Gaps

16. **test gap — no `test_analyzer.py`.** `analyzer.main()` (exit codes, signal
    handling, shutdown sequence, telemetry) is exercised only by demo.sh step 3 / manual
    runs. Fix: unit-test main() with a fake Sniffer/worker and tmp exports.

17. **test gap — `Sniffer` failure modes untested.** Nothing covers `running` after
    start (broken, see #2) or a failing AsyncSniffer surfacing its exception (see #3).
    Fix: test that a non-root start leaves `running` False / sets an exception.

18. **test gap — worker-thread death on exporter error untested.**
    `pipeline.py` has no test that a raising exporter is contained (see #9).
    Fix: test `run()` with a raising exporter in a subprocess/thread join.

19. **test gap — high-port boundary at exactly 49152 untested.** `test_high_port.py`
    checks 49151 (no) and 50000 (yes) but never the off-by-one case (see #1).
    Fix: assert the boundary matches the intended comparison.

20. **test gap — zero-delta EWMA path untested** (`store.py:159`, see #14).
    `test_store.py` only feeds strictly increasing timestamps.

21. **test gap — `SynScanDetector` source-cap eviction untested.**
    `syn_scan.py:139-143` (`_evict_sources_if_needed`) has no test (LRU pop of the
    min-`_source_last` source). Fix: exceed `max_sources` and assert eviction.

22. **test gap — `PlaintextDetector` `raw=None` path untested**
    (`plaintext.py:96`, marker tier with no payload), as are pcap-append vs
    csv-truncate across runs and `auto_detect_interface` prefix filtering.

## Doc / Code Drift

23. **README status is stale.** `README.md:11-12` claims "Phase 1 & Phase 2
    Complete … 43 tests" and "Phase 3 … Pending" — Phase 3 shipped at 82 tests.

24. **README flag table is incomplete.** `README.md:102-111` omits
    `--syn-threshold`, `--syn-window`, `--high-port`, `--alert-cooldown`.

25. **README references unimplemented UI.** `README.md:22` "CTRL-C or `q`" implies the
    Phase 4 rich UI (q-to-quit) which is not built; `README.md:48` still labels the
    diagram "Detector Engine (Phase 3 Hook)" — it is wired now.

26. **README names the wrong writer.** `README.md:21` says "RawPcapWriter"; the code
    uses `PcapWriter` (`export/pcap_writer.py:13`). Minor.

27. **high-port semantics doc drift.** The requirement ("dport > 49152") vs. CLI help
    "at/above" (`analyzer.py:87`) vs. code (`>=`) disagree — see #1; align all three.
