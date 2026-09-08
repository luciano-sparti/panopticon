"""Tests for the shared bounded-LRU eviction helper."""

from panopticon.core.lru import evict_lru


class TestEvictLru:
    def test_evicts_least_recent_until_under_cap(self):
        mapping = {"a": 10.0, "b": 5.0, "c": 7.0, "d": 3.0}
        removed = evict_lru(mapping, last_seen=lambda k: mapping[k], cap=2)
        assert removed == 2
        assert mapping == {"a": 10.0, "c": 7.0}

    def test_no_eviction_when_under_cap(self):
        mapping = {"a": 1.0}
        assert evict_lru(mapping, last_seen=lambda k: mapping[k], cap=5) == 0
        assert mapping == {"a": 1.0}

    def test_cap_zero_empties_all(self):
        mapping = {"a": 1.0, "b": 2.0}
        assert evict_lru(mapping, last_seen=lambda k: mapping[k], cap=0) == 2
        assert mapping == {}

    def test_on_evict_receives_keys_oldest_first(self):
        mapping = {"a": 1.0, "b": 2.0, "c": 3.0}
        evicted = []
        result = evict_lru(mapping, last_seen=lambda k: mapping[k], cap=1, on_evict=evicted.append)
        assert result == 2
        assert evicted == ["a", "b"]

    def test_parallel_recency_map_stays_in_sync(self):
        last = {"a": 1.0, "b": 2.0, "c": 3.0}
        mapping = dict(last)
        evict_lru(
            mapping,
            last_seen=last.__getitem__,
            cap=2,
            on_evict=lambda k: last.pop(k, None),
        )
        assert mapping == {"b": 2.0, "c": 3.0}
        assert last == {"b": 2.0, "c": 3.0}
