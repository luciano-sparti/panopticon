"""Tests for BPF filter presets and event matching."""

import pytest

from panopticon.capture.presets import (
    BPF_PRESETS,
    get_preset,
    match_preset_event,
    resolve_preset_filter,
)
from panopticon.core.event import PacketEvent


def test_bpf_presets_contain_expected_profiles():
    expected = {"all", "web", "dns", "non-lan", "suspicious-ports"}
    assert expected.issubset(set(BPF_PRESETS.keys()))
    for key in expected:
        preset = get_preset(key)
        assert preset is not None
        assert "name" in preset
        assert "filter" in preset
        assert "description" in preset


def test_resolve_preset_filter():
    assert resolve_preset_filter("web") == "tcp port 80 or tcp port 443"
    assert resolve_preset_filter("dns") == "udp port 53 or tcp port 53"
    assert resolve_preset_filter("all") == ""
    with pytest.raises(ValueError, match="unknown BPF preset"):
        resolve_preset_filter("nonexistent_preset_xyz")


def test_match_preset_event_web():
    web_ev = PacketEvent(0.0, "10.0.0.1", "1.1.1.1", "tcp", 54321, 443, 100, "https")
    dns_ev = PacketEvent(0.0, "10.0.0.1", "8.8.8.8", "udp", 54321, 53, 50, "dns")
    assert match_preset_event(web_ev, "web") is True
    assert match_preset_event(dns_ev, "web") is False
    assert match_preset_event(web_ev, "all") is True


def test_match_preset_event_dns():
    dns_udp = PacketEvent(0.0, "10.0.0.1", "8.8.8.8", "udp", 54321, 53, 50, "dns")
    dns_tcp = PacketEvent(0.0, "10.0.0.1", "8.8.8.8", "tcp", 54321, 53, 50, "dns")
    other = PacketEvent(0.0, "10.0.0.1", "1.1.1.1", "tcp", 54321, 80, 100, "http")
    assert match_preset_event(dns_udp, "dns") is True
    assert match_preset_event(dns_tcp, "dns") is True
    assert match_preset_event(other, "dns") is False


def test_match_preset_event_non_lan():
    lan_ev = PacketEvent(0.0, "192.168.1.10", "10.0.0.5", "tcp", 1234, 80, 100, "http")
    wan_ev = PacketEvent(0.0, "192.168.1.10", "93.184.216.34", "tcp", 1234, 80, 100, "http")
    assert match_preset_event(lan_ev, "non-lan") is False
    assert match_preset_event(wan_ev, "non-lan") is True


def test_match_preset_event_suspicious_ports():
    norm_web = PacketEvent(0.0, "10.0.0.1", "1.1.1.1", "tcp", 54321, 8080, 100, "")
    high_susp = PacketEvent(0.0, "10.0.0.1", "1.1.1.1", "tcp", 54321, 31337, 100, "")
    udp_port = PacketEvent(0.0, "10.0.0.1", "1.1.1.1", "udp", 54321, 31337, 100, "")
    assert match_preset_event(norm_web, "suspicious-ports") is False
    assert match_preset_event(high_susp, "suspicious-ports") is True
    assert match_preset_event(udp_port, "suspicious-ports") is False
