"""Offline GeoIP, ASN, and Threat Intelligence enrichment engine.

Provides fast, zero-external-dependency offline IP enrichment:
- Maps public IP addresses to Country code/name, Autonomous System (ASN), and Organization
  (e.g., AS15169 Google LLC, AS13335 Cloudflare, AS16509 Amazon AWS).
- Built-in cached threat intelligence feeds (Tor exit nodes, C2 infrastructure, botnets)
  supporting custom external feed ingestion.
- Thread-safe caching for zero-latency lookups during high-speed traffic processing.
"""

from __future__ import annotations

import csv
import ipaddress
import json
import os
import threading
from dataclasses import dataclass
from typing import Any, Union


@dataclass(frozen=True)
class GeoASNInfo:
    """Geographic location and Autonomous System metadata for an IP."""

    country_code: str
    country_name: str
    asn: str
    org: str
    city: str = ""

    def summary(self) -> str:
        """Formatted short description, e.g. ``US · AS15169 Google LLC``."""
        parts = []
        if self.country_code:
            parts.append(self.country_code)
        if self.asn and self.org:
            parts.append(f"{self.asn} {self.org}")
        elif self.asn:
            parts.append(self.asn)
        elif self.org:
            parts.append(self.org)
        return " · ".join(parts)


@dataclass(frozen=True)
class ThreatIntelInfo:
    """Threat intelligence finding for an IP address."""

    is_threat: bool
    threat_type: str
    source: str
    description: str


# Built-in curated offline ASN and Geo database for major global infrastructures,
# CDNs, cloud providers, and authoritative resolvers.
_ASNRangeItem = tuple[Union[ipaddress.IPv4Network, ipaddress.IPv6Network], str, str, str, str]
_BUILTIN_ASN_RANGES: list[_ASNRangeItem] = [
    # Google
    (ipaddress.ip_network("8.8.8.0/24"), "US", "United States", "AS15169", "Google LLC"),
    (ipaddress.ip_network("8.8.4.0/24"), "US", "United States", "AS15169", "Google LLC"),
    (ipaddress.ip_network("142.250.0.0/15"), "US", "United States", "AS15169", "Google LLC"),
    (ipaddress.ip_network("172.217.0.0/16"), "US", "United States", "AS15169", "Google LLC"),
    # Cloudflare
    (ipaddress.ip_network("1.1.1.0/24"), "US", "United States", "AS13335", "Cloudflare, Inc."),
    (ipaddress.ip_network("1.0.0.0/24"), "US", "United States", "AS13335", "Cloudflare, Inc."),
    (ipaddress.ip_network("104.16.0.0/12"), "US", "United States", "AS13335", "Cloudflare, Inc."),
    (ipaddress.ip_network("172.64.0.0/13"), "US", "United States", "AS13335", "Cloudflare, Inc."),
    # Quad9
    (ipaddress.ip_network("9.9.9.0/24"), "CH", "Switzerland", "AS19281", "Quad9"),
    (ipaddress.ip_network("149.112.112.0/24"), "CH", "Switzerland", "AS19281", "Quad9"),
    # GitHub / Fastly
    (ipaddress.ip_network("140.82.112.0/20"), "US", "United States", "AS36459", "GitHub, Inc."),
    (ipaddress.ip_network("151.101.0.0/16"), "US", "United States", "AS54113", "Fastly"),
    (ipaddress.ip_network("199.232.0.0/16"), "US", "United States", "AS54113", "Fastly"),
    # Amazon AWS
    (ipaddress.ip_network("3.0.0.0/9"), "US", "United States", "AS16509", "Amazon AWS"),
    (ipaddress.ip_network("13.32.0.0/15"), "US", "United States", "AS16509", "Amazon CloudFront"),
    (ipaddress.ip_network("52.0.0.0/11"), "US", "United States", "AS16509", "Amazon AWS"),
    (ipaddress.ip_network("54.0.0.0/11"), "US", "United States", "AS16509", "Amazon AWS"),
    # Microsoft
    (ipaddress.ip_network("13.64.0.0/11"), "US", "United States", "AS8075", "Microsoft"),
    (ipaddress.ip_network("20.0.0.0/11"), "US", "United States", "AS8075", "Microsoft"),
    (ipaddress.ip_network("51.140.0.0/14"), "GB", "United Kingdom", "AS8075", "Microsoft"),
    # Akamai
    (ipaddress.ip_network("23.0.0.0/12"), "US", "United States", "AS20940", "Akamai"),
    (ipaddress.ip_network("104.64.0.0/10"), "US", "United States", "AS20940", "Akamai"),
    # Hetzner
    (ipaddress.ip_network("88.198.0.0/16"), "DE", "Germany", "AS24940", "Hetzner Online GmbH"),
    (ipaddress.ip_network("136.243.0.0/16"), "DE", "Germany", "AS24940", "Hetzner Online GmbH"),
    (ipaddress.ip_network("168.119.0.0/16"), "DE", "Germany", "AS24940", "Hetzner Online GmbH"),
    # OVH
    (ipaddress.ip_network("51.254.0.0/15"), "FR", "France", "AS16276", "OVH SAS"),
    (ipaddress.ip_network("198.27.64.0/18"), "CA", "Canada", "AS16276", "OVH SAS"),
]

# Built-in curated threat intel indicators (Tor exit nodes, C2 channels, botnets).
_BUILTIN_THREAT_IPS: dict[str, tuple[str, str, str]] = {
    # Tor exit node sample fixtures
    "185.220.101.5": ("tor_exit", "Tor Project", "Known Tor Exit Node relay"),
    "185.220.101.6": ("tor_exit", "Tor Project", "Known Tor Exit Node relay"),
    "198.98.56.146": ("tor_exit", "Tor Project", "Known Tor Exit Node relay"),
    # Known malicious C2 / malware infrastructure
    "194.26.29.112": ("c2_server", "abuse.ch Feodo", "Active Emotet/QakBot C2 server"),
    "45.142.214.24": ("c2_server", "AlienVault OTX", "Cobalt Strike team server beacon"),
    "91.240.118.172": ("botnet", "abuse.ch SSLBL", "Malicious SSL botnet controller"),
}


class GeoEnricher:
    """Thread-safe offline GeoIP, ASN, and Threat Intelligence enricher."""

    def __init__(
        self,
        custom_asn_db: str | None = None,
        threat_feed: str | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self._asn_ranges: list[tuple[Any, str, str, str, str]] = list(_BUILTIN_ASN_RANGES)
        self._threats: dict[str, ThreatIntelInfo] = {
            ip: ThreatIntelInfo(is_threat=True, threat_type=t[0], source=t[1], description=t[2])
            for ip, t in _BUILTIN_THREAT_IPS.items()
        }
        self._geo_cache: dict[str, GeoASNInfo | None] = {}

        if custom_asn_db and os.path.exists(custom_asn_db):
            self.load_custom_asn_db(custom_asn_db)

        if threat_feed and os.path.exists(threat_feed):
            self.load_threat_feed(threat_feed)

    def load_custom_asn_db(self, path: str) -> int:
        """Load custom CIDR -> (country_code, country_name, asn, org) records from JSON or CSV.

        Returns count of loaded ranges.
        """
        loaded = 0
        try:
            if path.endswith(".json"):
                with open(path, encoding="utf-8") as fh:
                    data = json.load(fh)
                    for item in data:
                        cidr = item.get("cidr")
                        if not cidr:
                            continue
                        net = ipaddress.ip_network(cidr)
                        self._asn_ranges.append(
                            (
                                net,
                                item.get("country_code", "XX"),
                                item.get("country_name", "Unknown"),
                                item.get("asn", "AS0"),
                                item.get("org", "Unknown"),
                            )
                        )
                        loaded += 1
            elif path.endswith(".csv"):
                with open(path, encoding="utf-8") as fh:
                    reader = csv.reader(fh)
                    for row in reader:
                        if len(row) >= 5:
                            net = ipaddress.ip_network(row[0].strip())
                            self._asn_ranges.append(
                                (
                                    net,
                                    row[1].strip(),
                                    row[2].strip(),
                                    row[3].strip(),
                                    row[4].strip(),
                                )
                            )
                            loaded += 1
        except Exception:  # noqa: BLE001
            return 0
        with self._lock:
            self._geo_cache.clear()
        return loaded

    def load_threat_feed(self, path: str) -> int:
        """Load threat feed containing malicious IPs/CIDRs from JSON or text file.

        Returns count of loaded threats.
        """
        loaded = 0
        try:
            if path.endswith(".json"):
                with open(path, encoding="utf-8") as fh:
                    items = json.load(fh)
                    for item in items:
                        ip = item.get("ip")
                        if ip:
                            self._threats[ip.strip()] = ThreatIntelInfo(
                                is_threat=True,
                                threat_type=item.get("type", "malicious_ip"),
                                source=item.get("source", "custom_feed"),
                                description=item.get("description", "Reported threat"),
                            )
                            loaded += 1
            else:
                with open(path, encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split()
                        ip = parts[0]
                        ttype = parts[1] if len(parts) > 1 else "malicious_ip"
                        self._threats[ip] = ThreatIntelInfo(
                            is_threat=True,
                            threat_type=ttype,
                            source=os.path.basename(path),
                            description="Reported malicious address",
                        )
                        loaded += 1
        except Exception:  # noqa: BLE001
            return 0
        return loaded

    def lookup_geo_asn(self, ip: str) -> GeoASNInfo | None:
        """Look up Country and ASN info for ``ip``, or None if private/unknown."""
        if not ip:
            return None
        with self._lock:
            if ip in self._geo_cache:
                return self._geo_cache[ip]

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            with self._lock:
                self._geo_cache[ip] = None
            return None

        # Exclude RFC 1918 / loopback / link-local
        if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_private:
            with self._lock:
                self._geo_cache[ip] = None
            return None

        matched: GeoASNInfo | None = None
        for net, cc, cname, asn, org in self._asn_ranges:
            if addr in net:
                matched = GeoASNInfo(country_code=cc, country_name=cname, asn=asn, org=org)
                break

        with self._lock:
            self._geo_cache[ip] = matched
        return matched

    def lookup_threat(self, ip: str) -> ThreatIntelInfo | None:
        """Look up ``ip`` in the cached threat intelligence feed."""
        if not ip:
            return None
        return self._threats.get(ip.strip())


# Global default enricher instance
_DEFAULT_ENRICHER: GeoEnricher | None = None
_ENRICHER_LOCK = threading.Lock()


def get_default_enricher() -> GeoEnricher:
    """Return the global shared ``GeoEnricher`` singleton."""
    global _DEFAULT_ENRICHER
    with _ENRICHER_LOCK:
        if _DEFAULT_ENRICHER is None:
            _DEFAULT_ENRICHER = GeoEnricher()
        return _DEFAULT_ENRICHER
