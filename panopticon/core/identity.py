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


def resolve_owned_ips() -> Set[str]:
    """All of this host's own IPs: non-loopback interface addresses plus
    loopback (``127.0.0.1`` / ``::1``).

    Falls back to loopback-only when the kernel tables cannot be read, so
    the feature stays safe on platforms without ``/proc``.
    """
    owned: Set[str] = set(LOOPBACK_IPS)
    for path, parser in (
        ("/proc/net/fib_trie", _fib_trie_ips),
        ("/proc/net/if_inet6", _if_inet6_ips),
    ):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                owned |= parser(fh.read())
        except OSError:
            continue
    return owned
