"""Interactive key handling and shared dashboard UI state.

``UIControls`` owns everything the keyboard can mutate: the selector's
selected talker, the non-blocking inline prompts (tag add/remove, kill
confirmation), transient status messages, and the footer text. It is fed
raw bytes by ``KeyboardWatcher`` and rendered by the dashboard; it never
blocks on ``input()``.
"""

from __future__ import annotations

import os
import signal
import threading
import time
from typing import Callable, Dict, List, Optional

from panopticon.core.procs import local_pids_for_port

from .tables import DEFAULT_TOP_TALKERS, rank_talkers

# Escape sequence bytes for the ↑/↓ arrow keys (POSIX cbreak).
_KEY_UP = b"\x1b[A"
_KEY_DOWN = b"\x1b[B"

# Control-key alternates for ↑/↓ (k is taken by kill).
_KEY_CTRL_P = b"\x10"
_KEY_CTRL_N = b"\x0e"

# Status messages auto-expire after this many seconds.
STATUS_TTL = 4.0

# The tag namespace used by the pin toggle.
PINNED_TAG = "pinned"

# Zoom/view-mode id -> display name (single source of truth).
VIEW_MODE_NAMES: Dict[int, str] = {
    0: "all panes",
    1: "stream",
    2: "talkers",
    3: "alerts",
    4: "telemetry",
}


def legend_text(enable_kill: bool = False) -> str:
    """The persistent dashboard footer legend."""
    parts = [
        "q quit",
        "↑/↓ select",
        "Space freeze",
        "m metric",
        "1-4 zoom",
        "Enter inspect",
        "p pin",
        "t tag",
        "T untag",
    ]
    if enable_kill:
        parts.append("k kill")
    parts.append("? help")
    return " | ".join(parts)



def default_kill_resolver(
    ip: str, local_port: int, remote_port: Optional[int] = None
) -> List[int]:
    """Resolve the local PIDs owning a flow (via ``/proc``)."""
    return local_pids_for_port(local_port, remote_port=remote_port)



class UIControls:
    """Selector + prompt/status state driven by a feed of raw key bytes.

    Args:
        store: The ``StateStore`` whose tags/selection this controller mutates.
        enable_kill: When False, ``k`` only shows a "disabled" message.
        top_n: Number of talker rows the selector moves across.
        kill_resolver: ``(ip, local_port) -> pids`` used by the scoped kill.
    """

    def __init__(
        self,
        store,
        *,
        enable_kill: bool = False,
        top_n: int = DEFAULT_TOP_TALKERS,
        kill_resolver: Optional[Callable[[str, int], List[int]]] = None,
    ) -> None:
        self._store = store
        self.enable_kill = enable_kill
        self._top_n = top_n
        self._kill_resolver = kill_resolver or default_kill_resolver
        # RLock: feed() (keyboard thread) mutates while the render thread
        # reads the properties below; compound ops must not tear.
        self._lock = threading.RLock()
        self.selected_ip: Optional[str] = None
        self.prompt: Optional[dict] = None
        self.status = ""
        self._status_expires = 0.0
        self._esc: Optional[bytes] = None
        self.paused: bool = False
        self.metric: str = "bytes"
        self.view_mode: int = 0  # see VIEW_MODE_NAMES
        self.inspecting_ip: Optional[str] = None
        self.help_visible: bool = False
        # Alert severity filter: None=all, "warn"=warn+critical, "critical".
        self.alert_filter: Optional[str] = None

    # ------------------------------------------------------------------
    # Key input
    # ------------------------------------------------------------------

    def feed(self, data: bytes) -> None:
        """Process a chunk of raw key bytes (from the keyboard watcher)."""
        if not data:
            return
        with self._lock:
            for byte in data:
                b = bytes([byte])
                if self._esc is not None:
                    self._esc += b
                    if len(self._esc) == 3:
                        seq = self._esc
                        self._esc = None
                        self._on_escape(seq)
                    elif len(self._esc) > 3:
                        self._esc = None
                    continue
                if b == b"\x1b":
                    self._esc = b
                    continue
                self._on_key(b)
            # A lone ESC usually arrives as its own read chunk; flush it as
            # an Esc keypress instead of leaving it pending forever.
            if self._esc == b"\x1b":
                self._esc = None
                self._on_key(b"\x1b")

    def _on_escape(self, seq: bytes) -> None:
        if seq == _KEY_UP or seq == _KEY_CTRL_P:
            self._move_selection(-1)
        elif seq == _KEY_DOWN or seq == _KEY_CTRL_N:
            self._move_selection(1)

    def _on_key(self, b: bytes) -> None:
        if self.prompt is not None:
            self._on_prompt_key(b)
            return

        # Overlays first: ? toggles help; Enter/Esc dismiss overlays;
        # any other key closes help without acting underneath.
        if b == b"?":
            self.help_visible = not self.help_visible
            return
        if b == b"\x1b":
            if self.help_visible:
                self.help_visible = False
                self._set_status("help closed")
            elif self.inspecting_ip is not None:
                self.inspecting_ip = None
            elif self.selected_ip is not None:
                self.selected_ip = None
                self._set_status("selection cleared")
            return
        if b in (b"\r", b"\n"):
            if self.inspecting_ip is not None:
                self.inspecting_ip = None
            elif self.selected_ip:
                self.inspecting_ip = self.selected_ip
            return
        if self.help_visible and b != b"q":
            # Any key dismisses the help overlay (q still quits via watcher).
            self.help_visible = False
            return
        if self.inspecting_ip is not None:
            # Only Enter/Esc leave inspection mode; other keys are inert.
            return

        if b == b"q":
            return  # quit is handled by the watcher setting the stop event

        if b == b" ":
            self.paused = not self.paused
            self._set_status("STREAM FROZEN [PAUSED]" if self.paused else "STREAM RESUMED [LIVE]")
        elif b == b"m":
            self.metric = "pkts" if self.metric == "bytes" else "bytes"
            self._set_status(f"talkers sorted by {self.metric}")
        elif b in (b"0", b"1", b"2", b"3", b"4"):
            self.view_mode = int(b.decode("ascii"))
            self._set_status(f"view: {VIEW_MODE_NAMES[self.view_mode]}")
        elif b == b"\t":
            self.view_mode = (self.view_mode + 1) % len(VIEW_MODE_NAMES)
            self._set_status(f"view: {VIEW_MODE_NAMES[self.view_mode]}")
        elif b == b"j":  # vi-style down
            self._move_selection(1)
        elif b == _KEY_CTRL_N:
            self._move_selection(1)
        elif b == _KEY_CTRL_P:
            self._move_selection(-1)
        elif b == b"!":
            order = (None, "warn", "critical")
            idx = order.index(self.alert_filter)
            self.alert_filter = order[(idx + 1) % len(order)]
            label = {None: "all", "warn": "warn+", "critical": "critical"}[self.alert_filter]
            self._set_status(f"alert filter: {label}")
        elif b in (b"k", b"K", b"x"):
            self._on_kill()
        elif b == b"p":
            self._toggle_pin()

        elif b == b"t":
            self._begin_tag_prompt()
        elif b == b"T":
            self._begin_untag_prompt()

    def _on_prompt_key(self, b: bytes) -> None:
        prompt = self.prompt
        if prompt is None:
            return
        if prompt["kind"] == "confirm":
            if b == b"y":
                self._execute_kill(prompt)
            elif b in (b"n", b"\r", b"\n", b"\x1b"):
                self.prompt = None
                self._set_status("kill aborted")
            return
        if b == b"\x15":  # Ctrl+U clears the buffer
            prompt["buffer"] = ""
            return
        if b == b"\x1b":
            self.prompt = None
            self._set_status("prompt cancelled")
            return
        if b in (b"\r", b"\n"):
            self._submit_tag_prompt()
        elif b in (b"\x7f", b"\x08"):
            if not prompt["buffer"]:
                # Backspace on an empty buffer cancels the prompt.
                self.prompt = None
                self._set_status("prompt cancelled")
            else:
                prompt["buffer"] = prompt["buffer"][:-1]
        else:
            try:
                ch = b.decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001 - a bad byte just ends the prompt char
                return
            if ch.isprintable():
                prompt["buffer"] += ch


    # ------------------------------------------------------------------
    # Selector
    # ------------------------------------------------------------------

    def _ordered_talkers(self) -> List[str]:
        try:
            talkers = self._store.snapshot_talkers()
        except Exception:  # noqa: BLE001 - store may not be populated/ready
            return []
        return [ip for ip, _ in rank_talkers(talkers, metric=self.metric)][: self._top_n]


    def _move_selection(self, delta: int) -> None:
        ordered = self._ordered_talkers()
        if not ordered:
            return
        if self.selected_ip not in ordered:
            self.selected_ip = ordered[0] if delta >= 0 else ordered[-1]
            return
        index = ordered.index(self.selected_ip)
        index = max(0, min(len(ordered) - 1, index + delta))
        self.selected_ip = ordered[index]

    # ------------------------------------------------------------------
    # Pin / tag / kill actions
    # ------------------------------------------------------------------

    def _toggle_pin(self) -> None:
        ip = self.selected_ip
        if not ip:
            self._set_status("no talker selected (use ↑/↓)")
            return
        if PINNED_TAG in self._store.tags_for(ip):
            self._store.remove_tag(ip, PINNED_TAG)
            self._set_status(f"unpinned {ip}")
        else:
            self._store.add_tag(ip, PINNED_TAG)
            self._set_status(f"pinned {ip}")

    def _begin_tag_prompt(self) -> None:
        ip = self.selected_ip
        if not ip:
            self._set_status("no talker selected (use ↑/↓)")
            return
        self.prompt = {"kind": "add", "ip": ip, "buffer": ""}

    def _begin_untag_prompt(self) -> None:
        ip = self.selected_ip
        if not ip:
            self._set_status("no talker selected (use ↑/↓)")
            return
        self.prompt = {"kind": "remove", "ip": ip, "buffer": ""}

    def _submit_tag_prompt(self) -> None:
        prompt = self.prompt
        self.prompt = None
        if prompt is None:
            return
        tag = prompt["buffer"].strip()
        ip = prompt["ip"]
        if not tag:
            self._set_status("no tag entered")
            return
        if prompt["kind"] == "add":
            self._store.add_tag(ip, tag)
            self._set_status(f"tagged {ip} with {tag!r}")
        else:
            self._store.remove_tag(ip, tag)
            self._set_status(f"removed tag {tag!r} from {ip}")

    def _on_kill(self) -> None:
        ip = self.selected_ip
        if not ip:
            self._set_status("no talker selected (use ↑/↓)")
            return
        if not self.enable_kill:
            self._set_status("kill disabled (use --enable-kill)")
            return
        flow = self._store.snapshot_flow(ip)
        if flow is None:
            self._set_status(f"no known flow for {ip}")
            return
        remote_port = flow.get("remote_port")
        try:
            pids = self._kill_resolver(
                ip, flow["local_port"], remote_port=remote_port
            ) or []
        except TypeError:
            pids = self._kill_resolver(ip, flow["local_port"]) or []
        if not pids:
            self._set_status(
                f"no local process found for {ip} on port {flow['local_port']}"
            )
            return
        self.prompt = {
            "kind": "confirm",
            "ip": ip,
            "port": flow["local_port"],
            "pids": pids,
        }


    def _execute_kill(self, prompt: dict) -> None:
        self.prompt = None
        killed = []
        for pid in prompt["pids"]:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                continue
            except OSError as exc:  # noqa: BLE001 - surface, do not crash
                self._set_status(f"could not kill pid {pid}: {exc}")
                return
            killed.append(pid)
        if killed:
            self._set_status("SIGTERM sent to pid(s): " + ", ".join(map(str, killed)))

    # ------------------------------------------------------------------
    # Rendering state
    # ------------------------------------------------------------------

    @property
    def prompt_text(self) -> str:
        """The inline prompt to render in the footer (empty when idle)."""
        with self._lock:
            prompt = self.prompt
            if prompt is None:
                return ""
            if prompt["kind"] == "confirm":
                pids = ", ".join(str(pid) for pid in prompt["pids"])
                return (
                    f"kill {prompt['ip']} via local port {prompt['port']} "
                    f"(pid(s) {pids})? [y/n]"
                )
            verb = "tag" if prompt["kind"] == "add" else "remove tag"
            return f"{verb} {prompt['ip']}: {prompt['buffer']}▏"

    @property
    def footer_text(self) -> str:
        """The footer line: active prompt, transient status, or the legend."""
        with self._lock:
            if self.prompt is not None:
                return self.prompt_text
            if self.status and time.time() < self._status_expires:
                return self.status
            return legend_text(self.enable_kill)

    def _set_status(self, message: str, ttl: float = STATUS_TTL) -> None:
        with self._lock:
            self.status = message
            self._status_expires = time.time() + ttl
