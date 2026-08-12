"""
test_rules.py — Unit Tests for Detection Rules
------------------------------------------------
Uses Scapy to craft synthetic packets and verifies each rule fires correctly.
Run with: pytest tests/
"""

import pytest

try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.packet import Packet
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

pytestmark = pytest.mark.skipif(not SCAPY_AVAILABLE, reason="scapy not installed")


def make_ip(src="10.0.0.1", dst="10.0.0.2"):
    return IP(src=src, dst=dst)


# ── Rule 2: Excessive traffic ────────────────────────────────────────────────
def test_rule2_flags_flood():
    from netsentinel.rules import rule2_excessive_traffic
    packets = [make_ip() / TCP(dport=80) for _ in range(600)]
    findings = rule2_excessive_traffic(packets)
    assert len(findings) >= 1
    assert findings[0]["severity"] in ("MEDIUM", "HIGH", "CRITICAL")


def test_rule2_no_flag_below_threshold():
    from netsentinel.rules import rule2_excessive_traffic
    packets = [make_ip() / TCP(dport=80) for _ in range(100)]
    assert rule2_excessive_traffic(packets) == []


# ── Rule 6: ICMP flood ───────────────────────────────────────────────────────
def test_rule6_icmp_flood():
    from netsentinel.rules import rule6_icmp_flood
    packets = [make_ip() / ICMP(type=8) for _ in range(150)]
    findings = rule6_icmp_flood(packets)
    assert len(findings) == 1
    assert findings[0]["protocol"] == "ICMP"


# ── Rule 7: SYN flood ───────────────────────────────────────────────────────
def test_rule7_syn_flood():
    from netsentinel.rules import rule7_syn_flood
    # 250 SYNs, 0 ACKs -> 250 incomplete
    packets = [make_ip() / TCP(flags=0x02, dport=80) for _ in range(250)]
    findings = rule7_syn_flood(packets)
    assert len(findings) == 1


def test_rule7_no_flag_when_acked():
    from netsentinel.rules import rule7_syn_flood
    # equal SYNs and ACKs -> no flood
    syns = [make_ip() / TCP(flags=0x02, dport=80) for _ in range(250)]
    acks = [make_ip() / TCP(flags=0x10, dport=80) for _ in range(250)]
    assert rule7_syn_flood(syns + acks) == []


# ── Rule 8: Port scan ────────────────────────────────────────────────────────
def test_rule8_port_scan():
    from netsentinel.rules import rule8_port_scan
    # Hit 25 distinct ports
    packets = [make_ip() / TCP(dport=i) for i in range(1, 26)]
    findings = rule8_port_scan(packets)
    assert len(findings) == 1
    assert findings[0]["rule"] == 8


# ── run_all_rules integration ─────────────────────────────────────────────────
def test_run_all_rules_returns_list():
    from netsentinel.rules import run_all_rules
    packets = [make_ip() / TCP(dport=80)]
    result = run_all_rules(packets)
    assert isinstance(result, list)
