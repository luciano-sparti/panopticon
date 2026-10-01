"""Preflight + async capture via Scapy.

Owns the packet-capture half of the pipeline: verifies the platform can
capture (root / CAP_NET_RAW on POSIX, Npcap on Windows), resolves the
capture interface, and runs ``scapy.sendrecv.AsyncSniffer`` in a daemon
thread with ``store=False``. Each frame is parsed into a ``PacketEvent``
and pushed onto the shared queue as ``(raw_bytes, event)``; if the queue
is full the frame is counted as a queue-drop instead of blocking capture.
"""

from __future__ import annotations

import contextlib
import os
import queue
import socket
import sys
import threading
from functools import partial
from typing import Any

from scapy.arch import get_if_list
from scapy.config import conf
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
        with open("/proc/self/status", encoding="utf-8") as fh:
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
    except Exception:  # noqa: BLE001, S110 - probe absence is best-effort
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
        return f"interface {interface!r} not found; detected: " + ", ".join(ifaces)
    return _privilege_problem()


def validate_bpf_filter(interface: str, bpf_filter: str | None) -> str:
    """Return "" when ``bpf_filter`` compiles cleanly for ``interface``.

    Opens a throwaway libpcap listener socket so an invalid BPF expression is
    rejected at startup (clear exit-code-2 error) instead of surfacing
    asynchronously after capture starts. Caller must have passed
    ``preflight`` (capture privileges). Never raises: any failure — including
    the permission errors a de-privileged probe would produce — becomes a
    descriptive error string.
    """
    if not bpf_filter:
        return ""
    try:
        sock: Any = conf.L2listen(iface=interface, filter=bpf_filter)
    except Exception as exc:  # noqa: BLE001 - surface any compile/open error
        return f"invalid BPF filter {bpf_filter!r}: {exc}"
    with contextlib.suppress(Exception):
        sock.close()
    return ""


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
    except Exception:  # noqa: BLE001 - enumeration failure falls back to ""
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

    On a full queue the frame is counted as a queue drop instead of stalling
    capture. Any parse/serialization failure is contained here so one bad
    frame cannot kill the capture thread; the frame is counted as a parse
    failure. The two causes are tracked separately in the store.
    """
    if pkt is None:
        return
    try:
        event = parse(pkt)
        # Prefer the exact wire bytes libpcap delivered (PCAP fidelity);
        # fall back to re-serialization for synthetic/build piped packets
        # where ``pkt.original`` is empty.
        raw = pkt.original or bytes(pkt)
    except Exception:  # noqa: BLE001 - one bad frame must not stop capture
        store.increment_parse_failure()
        return
    try:
        packet_queue.put_nowait((raw, event))
    except queue.Full:
        store.increment_queue_drop()


# ----------------------------------------------------------------------
# Sniffer wrapper
# ----------------------------------------------------------------------


class AFPacketSniffer:
    """Linux AF_PACKET raw socket capture feeding (raw_bytes, PacketEvent) onto a queue.

    Uses Linux AF_PACKET / SOCK_RAW for direct kernel packet ingestion.
    """

    def __init__(
        self,
        interface: str,
        packet_queue: queue.Queue,
        store,
        bpf_filter: str | None = None,
    ) -> None:
        self._interface = interface
        self._packet_queue = packet_queue
        self._store = store
        self._bpf_filter = bpf_filter
        self._running = False
        self._exception: BaseException | None = None
        self._sock: socket.socket | None = None
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="panopticon-af-packet-sniffer",
            daemon=True,
        )

    @property
    def interface(self) -> str:
        return self._interface

    @property
    def running(self) -> bool:
        return self._running

    @property
    def exception(self) -> BaseException | None:
        return self._exception

    @property
    def capture_failed(self) -> bool:
        return self._exception is not None or (not self._running and not self._stop_event.is_set())

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        from scapy.layers.l2 import Ether

        try:
            if not hasattr(socket, "AF_PACKET"):
                raise OSError("AF_PACKET is only supported on Linux")
            eth_p_all = 0x0003
            self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(eth_p_all))
            if self._interface:
                self._sock.bind((self._interface, 0))
            self._sock.settimeout(0.5)
            self._running = True
            while not self._stop_event.is_set():
                try:
                    raw_data, _ = self._sock.recvfrom(65535)
                except (socket.timeout, TimeoutError):
                    continue
                except OSError:
                    break
                if not raw_data:
                    continue
                try:
                    pkt = Ether(raw_data)
                    handle_packet(self._packet_queue, self._store, pkt)
                except Exception:  # noqa: BLE001
                    self._store.increment_parse_failure()
        except BaseException as exc:  # noqa: BLE001
            self._exception = exc
        finally:
            self._running = False
            if self._sock is not None:
                with contextlib.suppress(Exception):
                    self._sock.close()

    def stop(self) -> None:
        self._stop_event.set()
        if self._sock is not None:
            with contextlib.suppress(Exception):
                self._sock.close()

    def join(self, timeout: float | None = None) -> None:
        self._thread.join(timeout)


class Sniffer:
    """Async capture feeding ``(raw_bytes, PacketEvent)`` onto a queue.

    The underlying capture engine runs inside its own daemon thread with
    ``store=False`` so Scapy never accumulates a frame backlog. Supports
    either Scapy's ``AsyncSniffer`` or direct Linux ``AF_PACKET``.
    """

    def __init__(
        self,
        interface: str,
        packet_queue: queue.Queue,
        store,
        bpf_filter: str | None = None,
        engine: str = "scapy",
    ) -> None:
        self._interface = interface
        self._bpf_filter = bpf_filter or None
        self._engine = engine.lower().strip()
        if self._engine == "af_packet" and hasattr(socket, "AF_PACKET"):
            self._impl: Any = AFPacketSniffer(
                interface=interface,
                packet_queue=packet_queue,
                store=store,
                bpf_filter=self._bpf_filter,
            )
            self._sniffer = None
            self._thread = None
        else:
            self._impl = None
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
        if self._impl is not None:
            return bool(self._impl.running)
        if self._sniffer is not None:
            return bool(self._sniffer.running)
        return False

    @property
    def exception(self) -> BaseException | None:
        if self._impl is not None:
            return self._impl.exception
        if self._sniffer is not None:
            return self._sniffer.exception
        return None

    @property
    def capture_failed(self) -> bool:
        if self._impl is not None:
            return bool(self._impl.capture_failed)
        if self._sniffer is not None:
            if self._sniffer.exception is not None:
                return True
            thread = self._sniffer.thread
            if thread is None:
                return False
            return not thread.is_alive() and not self._sniffer.running
        return False

    def start(self) -> None:
        if self._impl is not None:
            self._impl.start()
        elif self._thread is not None:
            self._thread.start()

    def stop(self) -> None:
        if self._impl is not None:
            self._impl.stop()
        elif self._sniffer is not None and getattr(self._sniffer, "running", False):
            with contextlib.suppress(Exception):
                self._sniffer.stop()

    def join(self, timeout: float | None = None) -> None:
        if self._impl is not None:
            self._impl.join(timeout)
        else:
            if self._thread is not None:
                self._thread.join(timeout)
            if self._sniffer is not None:
                internal = self._sniffer.thread
                if internal is not None and internal.is_alive():
                    internal.join(timeout)
