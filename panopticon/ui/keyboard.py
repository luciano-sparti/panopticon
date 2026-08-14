"""Non-blocking keyboard watcher for the dashboard (POSIX + Windows).

Listens for the ``q`` quit key in the background thread and sets a caller
supplied ``threading.Event`` when it is pressed. On POSIX the TTY is put
into cbreak mode (``termios``/``tty``) and stdin is polled with
``select.select([stdin], [], [], 0.1)``; on Windows ``msvcrt.kbhit`` is
polled. ``input()`` is never used, so the UI is never blocked on a key.

Degrades gracefully to a no-op when stdin is not a real, readable file
(e.g. CI, redirected input, or a test harness), so headless runs never
crash or spin because of the watcher.
"""

from __future__ import annotations

import os
import select
import sys
import threading

try:
    import msvcrt  # Windows only
except ImportError:  # pragma: no cover - POSIX
    msvcrt = None

try:
    import termios
    import tty
except ImportError:  # pragma: no cover - Windows
    termios = None
    tty = None

# POSIX quit key, as raw bytes read off the fd.
POSIX_QUIT_KEYS = (b"q",)
# Windows quit key, as returned by ``msvcrt.getwch``.
WINDOWS_QUIT_KEYS = ("q",)

DEFAULT_POLL_INTERVAL = 0.1


class KeyboardWatcher:
    """Watch stdin for the quit key without ever blocking the caller."""

    def __init__(
        self,
        stop_event: threading.Event,
        stdin=None,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
    ) -> None:
        self._stop = stop_event
        self._stdin = stdin if stdin is not None else sys.stdin
        self._poll = poll_interval
        self._exit = threading.Event()
        self._thread: threading.Thread | None = None
        self._termios_restore = None
        self._fd: int | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> "KeyboardWatcher":
        """Spawn the background watcher thread."""
        if self._thread is not None and self._thread.is_alive():
            return self
        self._exit.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="panopticon-keyboard",
            daemon=True,
        )
        self._thread.start()
        return self

    def stop(self, timeout: float = 1.0) -> "KeyboardWatcher":
        """Stop the watcher thread and restore the terminal if it was cbreak."""
        self._exit.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
        self._restore_terminal()
        return self

    @property
    def alive(self) -> bool:
        """True while the background thread is running."""
        return self._thread is not None and self._thread.is_alive()

    # ------------------------------------------------------------------
    # Thread body
    # ------------------------------------------------------------------

    def _run(self) -> None:
        try:
            fd = self._stdin.fileno()
        except (AttributeError, OSError, ValueError):
            return  # not a real stream (e.g. a test harness's fake stdin)

        self._fd = fd

        if msvcrt is not None:  # Windows
            self._run_windows()
            return

        # POSIX: only switch a real TTY to cbreak; pipes/files stay raw.
        try:
            isatty = os.isatty(fd)
        except (OSError, ValueError):
            isatty = False
        if isatty and termios is not None:
            try:
                self._termios_restore = termios.tcgetattr(fd)
                tty.setcbreak(fd, termios.TCSANOW)
            except (OSError, ValueError):
                self._termios_restore = None
                return
        self._run_posix()

    def _run_posix(self) -> None:
        while not self._exit.is_set() and not self._stop.is_set():
            try:
                ready, _, _ = select.select([self._fd], [], [], self._poll)
            except (OSError, ValueError):
                return
            if not ready:
                continue
            try:
                data = os.read(self._fd, 4096)
            except (OSError, ValueError):
                return
            if not data:  # EOF
                return
            if self._contains_quit(data):
                self._stop.set()
            self._drain()

    def _drain(self) -> None:
        """Consume any remaining queued keys so a late ``q`` is not missed."""
        while True:
            try:
                ready, _, _ = select.select([self._fd], [], [], 0)
            except (OSError, ValueError):
                return
            if not ready:
                return
            try:
                chunk = os.read(self._fd, 4096)
            except (OSError, ValueError):
                return
            if not chunk:
                return
            if self._contains_quit(chunk):
                self._stop.set()

    def _run_windows(self) -> None:
        while not self._exit.is_set() and not self._stop.is_set():
            try:
                if msvcrt.kbhit() and msvcrt.getwch() in WINDOWS_QUIT_KEYS:
                    self._stop.set()
            except Exception:  # noqa: BLE001 - console input went away
                return
            self._exit.wait(self._poll)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _contains_quit(self, data: bytes) -> bool:
        return any(key in data for key in POSIX_QUIT_KEYS)

    def _restore_terminal(self) -> None:
        if self._termios_restore is not None and termios is not None and self._fd is not None:
            try:
                termios.tcsetattr(self._fd, termios.TCSADRAIN, self._termios_restore)
            except (OSError, ValueError):
                pass
            self._termios_restore = None
