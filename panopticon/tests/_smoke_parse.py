"""Smoke harness: feed synthetic packets through the real parser.

Run via:  python -m panopticon.tests._smoke_parse
No root required. Builds raw frames with scapy and asserts the parser
extracts the expected fields, including the 'other'/fallback path.
"""
from __future__ import annotations

from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw, Padding


def _build() -> list:
    pkts = []
    # TCP with payload
    pkts.append(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
                TCP(sport=12345, dport=443, flags="PA") / Raw(b"GET / HTTP/1.1\r\n"))
    # UDP (DNS query on port 53)
    pkts.append(Ether() / IP(src="10.0.0.3", dst="10.0.0.4") /
                UDP(sport=5353, dport=53) / Raw(b"query"))
    # ICMP
    pkts.append(Ether() / IP(src="10.0.0.5", dst="10.0.0.6") / ICMP(type=8, code=0))
    # Corrupt/non-IP frame -> 'other' fallback
    pkts.append(Ether() / Padding(load=b"\x00\x01\x02\x03") / Raw(b"junk"))
    return pkts


def main() -> None:
    from panopticon.core.parser import parse
    from panopticon.core.event import service_for_port

    assert service_for_port(80) == "http"
    assert service_for_port(22) == "ssh"
    assert service_for_port(49152) == "ephemeral"

    events = [parse(p) for p in _build()]
    assert len(events) == 4, f"expected 4 events, got {len(events)}"

    tcp = events[0]
    assert tcp.proto == "tcp" and tcp.dport == 443 and tcp.service == "https", tcp
    udp = events[1]
    assert udp.proto == "udp" and udp.dport == 53 and udp.service == "dns", udp
    icmp = events[2]
    assert icmp.proto == "icmp", icmp
    other = events[3]
    assert other.proto == "other", other  # defensive fallback, no crash

    print(f"parse smoke OK: {len(events)} events (tcp/udp/icmp/other) parsed without error")


if __name__ == "__main__":
    main()
