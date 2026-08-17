"""Resolve the host's own IPs for the automatic ``self:`` tagging feature.

``StateStore`` tags any packet whose source or destination matches one of
these addresses with ``self:<hostname>`` (loopback addresses get
``self:localhost``). Resolution reads the kernel directly (``/proc``) and
deliberately does **not** use ``gethostbyname``, which on Debian returns
``127.0.1.1`` instead of the machine's real addresses.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
from typing import Set

# The addresses treated as "this machine" by the automatic self-tagging.
LOOPBACK_IPS = frozenset({"127.0.0.1", "::1"})

# IPv6 address scopes in /proc/net/if_inet6: 00=global, 40=site.
# Loopback (10) and link-local (20) addresses are excluded here and added
# separately via LOOPBACK_IPS.
_IF_INET6_SCOPES = frozenset({"00", "40"})

_IPV4_RE = re.compile(r"^\s*(?:\|--\s*)?(\d{1,3}(?:\.\d{1,3}){3})\s*$")


def hostname() -> str:
    """The host's node name (``os.uname().nodename`` with graceful fallback)."""
    try:
        uname = os.uname()
    except (AttributeError, OSError):
        uname = None
    if uname is not None and uname.nodename:
        return uname.nodename
    try:
        name = socket.gethostname()
    except OSError:
        name = ""
    return name or "localhost"


def _fib_trie_ips(text: str) -> Set[str]:
    """Local IPv4 addresses from a ``/proc/net/fib_trie`` dump.

    Every locally-assigned IPv4 address appears as a ``/32 host LOCAL``
    leaf whose parent line holds the address, e.g.::

        |-- 10.11.0.78
           /32 host LOCAL

    The loopback subnet (127.0.0.0/8) is excluded here because it is added
    explicitly through ``LOOPBACK_IPS``.
    """
    ips = set()
    prev = ""
    for line in text.splitlines():
        if "host LOCAL" in line:
            match = _IPV4_RE.match(prev)
            if match and not match.group(1).startswith("127."):
                ips.add(match.group(1))
        prev = line
    return ips


def _if_inet6_ips(text: str) -> Set[str]:
    """Global/site IPv6 interface addresses from a ``/proc/net/if_inet6`` dump.

    Each line is ``addr ifindex prefixlen scope flags name`` with the
    address as 32 hex digits (no colons).
    """
    ips = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        addr_hex, scope = parts[0], parts[3]
        if scope not in _IF_INET6_SCOPES:
            continue
        try:
            ips.add(str(ipaddress.IPv6Address(int(addr_hex, 16))))
        except ValueError:
            continue
    return ips


def _fallback_ips() -> Set[str]:
    """Local IPs discovered via Scapy / socket on platforms without ``/proc``."""
    ips: Set[str] = set()
    try:
        from scapy.arch import get_if_addr, get_if_list

        for iface in get_if_list():
            try:
                addr = get_if_addr(iface)
                if addr and addr not in ("0.0.0.0", "127.0.0.1", "::1"):
                    ips.add(addr)
            except Exception:
                continue
    except Exception:
        pass

    try:
        name = socket.gethostname()
        for res in socket.getaddrinfo(name, None):
            sockaddr = res[4]
            if sockaddr and isinstance(sockaddr, tuple) and sockaddr[0]:
                ip = str(sockaddr[0])
                if not ip.startswith("127.") and ip not in ("::1", "0.0.0.0"):
                    ips.add(ip)
    except Exception:
        pass
    return ips


def resolve_owned_ips() -> Set[str]:
    """All of this host's own IPs: non-loopback interface addresses plus
    loopback (``127.0.0.1`` / ``::1``).

    First attempts kernel-direct reading via ``/proc``; falls back to
    Scapy/socket interface enumeration on non-Linux platforms without ``/proc``.
    """
    owned: Set[str] = set(LOOPBACK_IPS)
    proc_found = False
    for path, parser in (
        ("/proc/net/fib_trie", _fib_trie_ips),
        ("/proc/net/if_inet6", _if_inet6_ips),
    ):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                parsed = parser(fh.read())
                if parsed:
                    owned |= parsed
                    proc_found = True
        except OSError:
            continue
    if not proc_found:
        owned |= _fallback_ips()
    return owned

