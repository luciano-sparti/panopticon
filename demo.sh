#!/usr/bin/env bash
# Panopticon — a quick tour of the engine + a live-capture option.
#
# Sets up a virtualenv if needed, then runs the no-privilege functional checks
# (unit tests, CLI self-checks, a synthetic packet pipeline) and, optionally,
# a real capture if you pass LIVE=1 (requires root / CAP_NET_RAW).
#
# Nothing is touched outside the repo + a temp dir that is cleaned up on exit.
# Proof result: ./demo.sh (no LIVE) green end-to-end, exit 0 — verified 2026-08-14.
#
# Usage:
#   ./demo.sh            # the full tour (no root required)
#   LIVE=1 ./demo.sh     # also attempt a real 5s capture (needs sudo)
#   ./demo.sh pytest     # a single step, by name
#   ./demo.sh 2          # ... or by number (1..7)
#
# Steps: 1 pytest · 2 help · 3 preflight · 4 parse · 5 detect · 6 export · 7 live

set -euo pipefail
cd "$(dirname "$0")"

# ── environment ──────────────────────────────────────────────────────────────
PY="${PANOPTICON_PYTHON:-python3}"
VENV_DIR=".venv"
if [[ ! -d "$VENV_DIR" ]]; then
  echo "Creating virtualenv ($VENV_DIR)..."
  "$PY" -m venv "$VENV_DIR"
  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"
  pip install --quiet -r requirements.txt
elif [[ -f "$VENV_DIR/bin/activate" ]]; then
  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"
  # Self-heal a stale/broken venv: reinstall deps only when they are missing
  # (the import check is local; no network is touched when already satisfied).
  if ! "$VENV_DIR/bin/python" -c 'import scapy, pytest, rich' >/dev/null 2>&1; then
    echo "Reinstalling dependencies into $VENV_DIR..."
    pip install --quiet -r requirements.txt
  fi
else
  echo "demo.sh: $VENV_DIR exists but has no bin/activate (unsupported layout?)" >&2
  exit 2
fi
PYEXEC="$(command -v python)"

WORKDIR="$(mktemp -d -t panopticon-demo.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

# ── colors / helpers (mirrors FATES demo.sh) ──────────────────────────────────
C_SECTION=$'\033[1;36m'
C_CMD=$'\033[1;33m'
C_DIM=$'\033[2m'
C_RESET=$'\033[0m'

section() { printf '\n%s▸ %s%s\n' "$C_SECTION" "$1" "$C_RESET"; }
note()    { printf '%s# %s%s\n' "$C_DIM" "$1" "$C_RESET"; }

run_py() {
  printf '\n%s$ python -m %s%s\n' "$C_CMD" "$*" "$C_RESET"
  "$PYEXEC" -m "$@"
}

have_capture_privs() {
  # Root, or CAP_NET_RAW (Linux capability bit 13) set on this process.
  [[ "$(id -u)" -eq 0 ]] && return 0
  [[ ! -r /proc/self/status ]] && return 1
  local cap
  cap="$(awk '/^CapEff:/{print $2}' /proc/self/status)"
  [[ -n "$cap" ]] && (( (16#$cap & (1 << 13)) != 0 ))
}

# ── step selection ────────────────────────────────────────────────────────────
STEP="${1:-all}"
names=(pytest help preflight parse detect export live)
if [[ "$STEP" =~ ^[0-9]+$ ]]; then
  num=$((10#$STEP))
  if (( num < 1 || num > ${#names[@]} )); then
    printf 'demo.sh: step number out of range (1..%d): %s\n' "${#names[@]}" "$STEP" >&2
    exit 2
  fi
  STEP="${names[$((num - 1))]}"
elif [[ "$STEP" != "all" ]]; then
  ok=0
  for n in "${names[@]}"; do [[ "$n" == "$STEP" ]] && ok=1; done
  if (( ok == 0 )); then
    printf 'demo.sh: unknown step %q (options: all %s)\n' "$STEP" "${names[*]}" >&2
    exit 2
  fi
fi
want() { [[ "$STEP" == "all" || "$STEP" == "$1" ]]; }

# ── 1. unit tests ─────────────────────────────────────────────────────────────
if want pytest; then
  section "1/7 — pytest (full unit + integration suite, no root)"
  "$PYEXEC" -m pytest panopticon/tests -q
fi

# ── 2. CLI help ───────────────────────────────────────────────────────────────
if want help; then
  section "2/7 — panopticon.analyzer --help (every flag)"
  run_py panopticon.analyzer --help
fi

# ── 3. preflight abort (no root) ──────────────────────────────────────────────
if want preflight; then
  section "3/7 — preflight without privileges (should abort cleanly, exit 2)"
  if have_capture_privs; then
    note "Running with capture privileges already — the unprivileged abort path"
    note "cannot be demonstrated here. Use step 7 (LIVE) to exercise real capture."
  else
    note "Real sniffing needs root / CAP_NET_RAW; without it the CLI refuses to start."
    set +e
    "$PYEXEC" -m panopticon.analyzer --interface lo --export-pcap "$WORKDIR/out.pcap" --export-csv "$WORKDIR/out.csv"
    RC=$?
    set -e
    note "exit code: $RC (expected 2 = privilege/preflight failure)"
  fi
fi

# ── 4. parser smoke (synthetic packets) ───────────────────────────────────────
if want parse; then
  section "4/7 — parser smoke test (craft synthetic TCP/UDP/ICMP + junk)"
  run_py panopticon.tests._smoke_parse
fi

# ── 5. detection smoke (synthetic events → alerts) ────────────────────────────
if want detect; then
  section "5/7 — detection smoke test (feed a SYN scan + plaintext + high-port)"
  run_py panopticon.tests._smoke_detect
fi

# ── 6. exporter round-trip (PCAP + CSV from synthetic frames) ─────────────────
if want export; then
  section "6/7 — exporter round-trip (write + re-read .pcap and .csv)"
  run_py panopticon.tests._smoke_export
fi

# ── 7. live capture (optional, requires root) ────────────────────────────────
if want live; then
  if [[ "${LIVE:-0}" != "1" ]]; then
    note "Skipping live capture. Re-run with LIVE=1 and sudo to exercise real sniffing."
  else
    section "7/7 — live capture (5s on auto-detected interface, needs root)"
    note "Writes $WORKDIR/session.pcap and $WORKDIR/session.csv, then stops."
    note "Uses the venv python explicitly under sudo (sudo drops the venv from PATH)."
    sudo "$VENV_DIR/bin/python" -m panopticon.analyzer \
      --export-pcap "$WORKDIR/session.pcap" \
      --export-csv  "$WORKDIR/session.csv" \
      --refresh 0.5 &
    CAP_PID=$!
    sleep 5
    kill -INT "$CAP_PID" 2>/dev/null || true
    wait "$CAP_PID" 2>/dev/null || true
    note "pcap bytes: $(stat -c%s "$WORKDIR/session.pcap" 2>/dev/null || echo 0)"
    note "csv bytes:  $(stat -c%s "$WORKDIR/session.csv" 2>/dev/null || echo 0)"
  fi
fi

if want all; then
  echo
  echo "Tour complete. For a real capture:  LIVE=1 sudo ./demo.sh live"
fi
