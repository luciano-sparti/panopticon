"""Resolve the local processes owning a flow, matched by local port.

Pure ``/proc`` walking (no shelling out to ``ss``/``lsof``): every socket
inode currently held by a process is collected from ``/proc/<pid>/fd``
symlinks, then the kernel's ``/proc/net/{tcp,tcp6,udp,udp6}`` tables are
scanned for the requested local port and the inode field is identified by
matching it against that collected set. Matching by value makes the parser
immune to the inode-column layout changing between kernel versions.
"""

from __future__ import annotations

import os
from collections.abc import Iterable

# Header token of every /proc/net/{tcp,udp,tcp6,udp6} table.
_HEADER = "sl"

_SOCKET_PREFIX = "socket:["
_SOCKET_SUFFIX = "]"


def _read_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


def _all_socket_inodes(proc_root: str) -> set[str]:
    """Every socket inode currently referenced by some process's fd table."""
    inodes: set[str] = set()
    try:
        entries = os.listdir(proc_root)
    except OSError:
        return inodes
    for name in entries:
        if not name.isdigit():
            continue
        fd_dir = os.path.join(proc_root, name, "fd")
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if target.startswith(_SOCKET_PREFIX) and target.endswith(_SOCKET_SUFFIX):
                inodes.add(target[len(_SOCKET_PREFIX) : -len(_SOCKET_SUFFIX)])
    return inodes


def _inet_table_inodes(
    text: str,
    port: int,
    candidates: set[str],
    remote_port: int | None = None,
) -> set[str]:
    """Candidate socket inodes bound to ``port`` in a ``/proc/net/*`` dump.

    Each data row's local end is ``<addr-hex>:<port-hex>``; the inode
    column is identified by matching against ``candidates``. When
    ``remote_port`` is specified, exact 4-tuple flow matches (local_port +
    remote_port) take precedence over general listening port matches.
    """
    want_local = f":{port:04X}"
    want_remote = f":{remote_port:04X}" if remote_port is not None and remote_port > 0 else None

    flow_matched: set[str] = set()
    port_matched: set[str] = set()

    for line in text.splitlines():
        if not line.strip() or line.startswith(_HEADER):
            continue
        fields = line.split()
        if len(fields) < 4 or not fields[1].endswith(want_local):
            continue
        is_exact_flow = want_remote is not None and fields[2].endswith(want_remote)
        for field in fields[4:]:
            if field in candidates:
                if is_exact_flow:
                    flow_matched.add(field)
                port_matched.add(field)

    return flow_matched if flow_matched else port_matched


def _pids_for_socket_inodes(proc_root: str, inodes: Iterable[str]) -> list[int]:
    """PIDs whose fd table references any of the given socket inodes."""
    if not inodes:
        return []
    wanted = {f"socket:[{inode}]" for inode in inodes}
    pids: list[int] = []
    try:
        entries = os.listdir(proc_root)
    except OSError:
        return []
    for name in entries:
        if not name.isdigit():
            continue
        fd_dir = os.path.join(proc_root, name, "fd")
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if target in wanted:
                pids.append(int(name))
                break
    return sorted(pids)


def local_pids_for_port(
    port: int,
    proc_root: str = "/proc",
    remote_port: int | None = None,
) -> list[int]:
    """PIDs with a socket bound to the given local port (Linux ``/proc``).

    Optionally matches ``remote_port`` to prioritize established 4-tuple flows.
    """
    candidates = _all_socket_inodes(proc_root)
    if not candidates:
        return []
    matched: set[str] = set()
    for table in ("tcp", "tcp6", "udp", "udp6"):
        matched |= _inet_table_inodes(
            _read_text(os.path.join(proc_root, "net", table)),
            port,
            candidates,
            remote_port=remote_port,
        )
    return _pids_for_socket_inodes(proc_root, matched)
