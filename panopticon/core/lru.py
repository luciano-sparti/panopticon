"""Bounded LRU eviction, shared by every `O(n)` eviction site.

The pipeline keeps several unlimited-growth collections bounded: top
talkers in the state store, SYN-scan sources, and high-port dedup flows.
All three evict by "least recent activity" — a per-key timestamp stored
either inline (the talker record / dedup map value) or in a parallel
``{key: ts}`` map — so the triplicated ``min`` scan lives in one place.
"""

from __future__ import annotations

from collections.abc import Callable, MutableMapping
from typing import TypeVar

K = TypeVar("K")
V = TypeVar("V")


def evict_lru(
    mapping: MutableMapping[K, V],
    last_seen: Callable[[K], float],
    cap: int,
    on_evict: Callable[[K], object] | None = None,
) -> int:
    """Evict least-recently-active keys until ``mapping`` fits under ``cap``.

    ``last_seen(key)`` returns the key's last-activity timestamp (typically
    ``dict.__getitem__`` or a lookup into a parallel ``{key: ts}`` map); the
    entry with the smallest value is removed first. ``on_evict``, if given,
    is called with each removed key so callers can clean a parallel
    structure; its return value is ignored.

    Eviction is bounded-LRU semantics and costs O(n) per removed key, which
    is fine here: caps are in the thousands and eviction runs at most once
    per insert/request.

    Returns the number of keys evicted.
    """
    removed = 0
    while len(mapping) > cap:
        oldest = min(mapping, key=last_seen)
        del mapping[oldest]
        removed += 1
        if on_evict is not None:
            on_evict(oldest)
    return removed
