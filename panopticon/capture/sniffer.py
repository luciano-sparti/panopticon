"""Preflight + async capture via Scapy.

Owns the packet-capture half of the pipeline: verifies the platform can
capture (root / CAP_NET_RAW on POSIX, Npcap on Windows), resolves the
capture interface, and runs ``scapy.sendrecv.AsyncSniffer`` in a daemon
thread with ``store=False``. Each frame is parsed into a ``PacketEvent``
and pushed onto the shared queue as ``(raw_bytes, event)``; if the queue
is full the frame is counted as dropped instead of blocking capture.
"""

from __future__ import annotations

import os
import queue
import sys
import threading
from functools import partial
from typing import Optional

from scapy.arch import get_if_list
from scapy.sendrecv import AsyncSniffer

from ..core.parser import parse

# CAP_NET_RAW is capability bit 13 in the Linux capability bitmap.
CAP_NET_RAW = 13

# Interface names treated as loopback / pseudo devices by auto-detection.
_LOOPBACK_NAMES = {"lo", "lo0", "any", "all"}
_PSEUDO_PREFIXES = (
    "docker",
    "veth",
    "virbr",
    "br-",
    "nflog",
    "nfqueue",
    "bluetooth",
    "tap",
    "tun",
    "utun",
    "vmnet",
    "vboxnet",
    "ppp",
    "wg",
)


# ----------------------------------------------------------------------
# Preflight checks (clear abort messages for the CLI)
# ----------------------------------------------------------------------

def _cap_net_raw_enabled() -> bool:
    """True when CAP_NET_RAW is granted to this process (Linux)."""
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("CapEff:"):
                    cap = int(line.split(":", 1)[1].strip(), 16)
                    return bool((cap >> CAP_NET_RAW) & 1)
    except OSError:
        pass
    return False


def _windows_npcap_problem() -> str:
    """Best-effort Npcap presence check; returns a problem string or ``""``."""
    try:
        from scapy.arch.windows import get_windows_if_list

        if get_windows_if_list():
            return ""
    except Exception:
        pass
    return (
        "Npcap does not appear to be installed (Windows). Install Npcap "
        "from https://npcap.com and re-run as Administrator."
    )


def _privilege_problem() -> str:
    """Return a privilege problem description, or ``""`` when capture is OK."""
    if os.name == "nt":
        return _windows_npcap_problem()
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return ""
    if sys.platform == "linux" and _cap_net_raw_enabled():
        return ""
    return (
        "running without capture privileges: re-run as root, grant "
        "CAP_NET_RAW/CAP_NET_ADMIN (setcap cap_net_raw,cap_net_admin=eip), "
        "or install Npcap on Windows."
    )


def preflight(interface: str) -> str:
    """Run capture-readiness checks for ``interface``.

    Returns an empty string when capture can proceed, otherwise a clear
    description of what is missing so the CLI can abort.
    """
    try:
        ifaces = get_if_list()
    except Exception as exc:  # noqa: BLE001 - surface any enum failure
        return f"could not enumerate network interfaces: {exc}"
    if not ifaces:
        return "no network interfaces found (is libpcap/Npcap installed?)"
    if interface and interface not in ifaces:
        return (
            f"interface {interface!r} not found; detected: "
            + ", ".join(ifaces)
        )
    return _privilege_problem()


def _is_pseudo_interface(name: str) -> bool:
    if name in _LOOPBACK_NAMES:
        return True
    return any(name.startswith(prefix) for prefix in _PSEUDO_PREFIXES)


# sysfs is the dependency-free source for per-interface link state.
_SYS_CLASS_NET = "/sys/class/net"


def _read_sys_iface_field(name: str, field: str) -> str:
    """Read a trimmed ``/sys/class/net/<name>/<field>`` value, or ``""``."""
    try:
        with open(
            os.path.join(_SYS_CLASS_NET, name, field),
            "r",
            encoding="utf-8",
        ) as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _iface_operstate(name: str) -> str:
    """Link-operational state of ``name`` from sysfs (e.g. ``"up"``)."""
    return _read_sys_iface_field(name, "operstate")


def _iface_has_address(name: str) -> bool:
    """True when the interface carries a non-zero assigned MAC address."""
    addr = _read_sys_iface_field(name, "address")
    return bool(addr) and addr != "00:00:00:00:00:00"


def _select_interface(names: list) -> str:
    """Rank candidate interfaces: up+addressed > up > any non-pseudo."""
    up_addressed: list = []
    up: list = []
    for name in names:
        if _is_pseudo_interface(name):
            continue
        if _iface_operstate(name) in {"up", "lower_up"}:
            if _iface_has_address(name):
                up_addressed.append(name)
            up.append(name)
    if up_addressed:
        return up_addressed[0]
    if up:
        return up[0]
    for name in names:
        if not _is_pseudo_interface(name):
            return name
    return ""


def auto_detect_interface() -> str:
    """Pick the first usable non-loopback interface, else ``""``."""
    try:
        ifaces = get_if_list()
    except Exception:
        return ""
    return _select_interface(ifaces)


# ----------------------------------------------------------------------
# Queue feeding
# ----------------------------------------------------------------------

def handle_packet(
    packet_queue: queue.Queue,
    store,
    pkt,
) -> None:
    """Parse ``pkt`` and enqueue ``(raw_bytes, event)`` non-blocking.

    On a full queue the frame is counted as dropped instead of stalling
    capture. Any parse/serialization failure is contained here so one bad
    frame cannot kill the capture thread; the frame is counted as dropped.
    """
    if pkt is None:
        return
    try:
        event = parse(pkt)
        raw = bytes(pkt)
    except Exception:  # noqa: BLE001 - one bad frame must not stop capture
        store.increment_dropped()
        return
    try:
        packet_queue.put_nowait((raw, event))
    except queue.Full:
        store.increment_dropped()


# ----------------------------------------------------------------------
# Sniffer wrapper
# ----------------------------------------------------------------------

class Sniffer:
    """Async capture feeding ``(raw_bytes, PacketEvent)`` onto a queue.

    The underlying ``AsyncSniffer`` runs inside its own daemon thread with
    ``store=False`` so Scapy never accumulates a frame backlog.
    """

    def __init__(
        self,
        interface: str,
        packet_queue: queue.Queue,
        store,
        bpf_filter: Optional[str] = None,
    ) -> None:
        self._interface = interface
        self._bpf_filter = bpf_filter or None
        self._sniffer = AsyncSniffer(
            iface=interface,
            filter=self._bpf_filter,
            prn=partial(handle_packet, packet_queue, store),
            store=False,
        )
        self._thread = threading.Thread(
            target=self._sniffer.start,
            name="panopticon-sniffer",
            daemon=True,
        )

    @property
    def interface(self) -> str:
        return self._interface

    @property
    def running(self) -> bool:
        return bool(self._sniffer.running)

    @property
    def exception(self) -> Optional[BaseException]:
        """Capture-thread exception, or ``None`` while capture is healthy.

        Scapy's ``AsyncSniffer`` swallows capture errors into this attribute
        (bad BPF filter, permission change, removed interface, ...); it is the
        authoritative signal that capture has failed.
        """
        return self._sniffer.exception

    @property
    def capture_failed(self) -> bool:
        """True once the capture loop has ended or raised an error."""
        if self._sniffer.exception is not None:
            return True
        thread = self._sniffer.thread
        if thread is None:
            return False  # the internal sniffer has not been started yet
        return not thread.is_alive() and not self._sniffer.running

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        """Close the capture socket. Safe to call before the thread runs."""
        if not getattr(self._sniffer, "running", False):
            return
        try:
            self._sniffer.stop()
        except Exception:  # noqa: BLE001 - best-effort socket close
            pass

    def join(self, timeout: Optional[float] = None) -> None:
        self._thread.join(timeout)
