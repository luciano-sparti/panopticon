"""Tests for GeoIP, ASN, and Threat Intelligence enrichment."""

import json

from panopticon.core.enrichment import (
    GeoASNInfo,
    GeoEnricher,
)
from panopticon.core.event import PacketEvent
from panopticon.core.store import StateStore
from panopticon.detection.threat_intel import ThreatIntelDetector


def test_geo_asn_summary():
    info = GeoASNInfo(
        country_code="US",
        country_name="United States",
        asn="AS15169",
        org="Google LLC",
    )
    assert info.summary() == "US · AS15169 Google LLC"


def test_builtin_geo_asn_lookups():
    enricher = GeoEnricher()
    # Google public DNS
    google = enricher.lookup_geo_asn("8.8.8.8")
    assert google is not None
    assert google.country_code == "US"
    assert "AS15169" in google.asn

    # Cloudflare
    cf = enricher.lookup_geo_asn("1.1.1.1")
    assert cf is not None
    assert cf.country_code == "US"
    assert "AS13335" in cf.asn

    # Private IP yields None
    assert enricher.lookup_geo_asn("192.168.1.1") is None
    assert enricher.lookup_geo_asn("10.0.0.1") is None
    assert enricher.lookup_geo_asn("127.0.0.1") is None


def test_custom_threat_feed_loading(tmp_path):
    feed_path = tmp_path / "threats.json"
    threats = [
        {
            "ip": "203.0.113.55",
            "type": "c2_beacon",
            "source": "test_intel",
            "description": "Test C2 IP",
        }
    ]
    feed_path.write_text(json.dumps(threats), encoding="utf-8")

    enricher = GeoEnricher(threat_feed=str(feed_path))
    threat = enricher.lookup_threat("203.0.113.55")
    assert threat is not None
    assert threat.is_threat is True
    assert threat.threat_type == "c2_beacon"
    assert threat.source == "test_intel"


def test_threat_intel_detector_triggers_alert():
    enricher = GeoEnricher()
    detector = ThreatIntelDetector(enricher=enricher)
    # 194.26.29.112 is in built-in malicious C2 feeds
    malicious_ev = PacketEvent(
        timestamp=100.0,
        src="192.168.1.10",
        dst="194.26.29.112",
        proto="tcp",
        sport=45678,
        dport=443,
        size=250,
        service="https",
    )
    alert = detector.process_event(malicious_ev, now=100.0)
    assert alert is not None
    assert alert.kind == "threat_intel"
    assert alert.severity == "critical"
    assert "194.26.29.112" in alert.summary

    # Normal IP does not trigger
    normal_ev = PacketEvent(
        timestamp=101.0,
        src="192.168.1.10",
        dst="1.1.1.1",
        proto="tcp",
        sport=45678,
        dport=443,
        size=250,
        service="https",
    )
    assert detector.process_event(normal_ev, now=101.0) is None


def test_store_talker_snapshot_enriched_with_geo_asn():
    enricher = GeoEnricher()
    store = StateStore(enricher=enricher)
    ev = PacketEvent(
        timestamp=1.0,
        src="8.8.8.8",
        dst="10.0.0.1",
        proto="udp",
        sport=53,
        dport=54321,
        size=120,
        service="dns",
    )
    store.update(ev)
    snap = store.snapshot_talkers()
    assert "8.8.8.8" in snap
    talker = snap["8.8.8.8"]
    assert talker["geo"] == "US"
    assert "AS15169" in talker["asn"]
    assert "Google" in talker["org"]
