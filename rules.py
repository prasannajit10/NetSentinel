"""
rules.py — 8 Anomaly Detection Rules
--------------------------------------
Each function takes a list of Scapy packets and returns a list of Finding dicts.

The 8 rules directly mirror Assignment 19 from CSE3156 Digital Forensics:
  Rule 1 — Common destination ports (TCP/UDP)
  Rule 2 — Excessive Traffic (DDoS)
  Rule 3 — Packet count and size
  Rule 4 — Unsolicited ARP replies
  Rule 5 — Unusually large DNS responses
  Rule 6 — Excessive ICMP Echo requests
  Rule 7 — Excessive TCP SYN (SYN flood)
  Rule 8 — IP scanning excessive ports

A Finding is a plain dict:
  {
    "rule": int,
    "name": str,
    "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
    "src": str,
    "dst": str,
    "protocol": str,
    "count": int,
    "detail": str,
  }
"""

from collections import defaultdict

# ---------------------------------------------------------------------------
# Thresholds — tweak these to tune sensitivity
# ---------------------------------------------------------------------------
DDOS_THRESHOLD        = 500   # packets per source IP to flag as DDoS
LARGE_PACKET_BYTES    = 1400  # bytes above which a packet is "large"
TINY_PACKET_BYTES     = 20    # bytes below which a packet is "tiny"
LARGE_DNS_BYTES       = 512   # DNS response payload larger than this
ICMP_FLOOD_THRESHOLD  = 100   # ICMP echo requests from one source
SYN_FLOOD_THRESHOLD   = 200   # SYN packets from one source without ACK
PORT_SCAN_THRESHOLD   = 20    # distinct dst ports from one source
COMMON_PORTS          = {80, 443, 22, 53, 21, 25, 110, 143, 3306, 8080}


def _severity(count, low, med, high):
    """Map a count to a severity label using three thresholds."""
    if count >= high:   return "CRITICAL"
    if count >= med:    return "HIGH"
    if count >= low:    return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Rule 1 — Common destination ports
# ---------------------------------------------------------------------------
def rule1_common_ports(packets) -> list:
    """
    Flag TCP/UDP flows to non-standard ports.
    Non-standard means NOT in COMMON_PORTS.
    Groups by (src_ip, dst_port) and reports ones with > 10 packets.
    """
    from scapy.layers.inet import IP, TCP, UDP
    counter = defaultdict(int)

    for pkt in packets:
        if IP in pkt:
            if TCP in pkt and pkt[TCP].dport not in COMMON_PORTS:
                counter[(pkt[IP].src, pkt[TCP].dport, "TCP")] += 1
            elif UDP in pkt and pkt[UDP].dport not in COMMON_PORTS:
                counter[(pkt[IP].src, pkt[UDP].dport, "UDP")] += 1

    findings = []
    for (src, dport, proto), count in counter.items():
        if count > 10:
            findings.append({
                "rule": 1, "name": "Uncommon destination port",
                "severity": _severity(count, 10, 50, 200),
                "src": src, "dst": f"port {dport}", "protocol": proto,
                "count": count,
                "detail": f"{count} packets to non-standard port {dport}/{proto}",
            })
    return findings


# ---------------------------------------------------------------------------
# Rule 2 — Excessive traffic (DDoS indicator)
# ---------------------------------------------------------------------------
def rule2_excessive_traffic(packets) -> list:
    """
    Count packets per source IP. Any IP exceeding DDOS_THRESHOLD
    is flagged as a potential DDoS source or compromised host.
    """
    from scapy.layers.inet import IP
    counter = defaultdict(int)

    for pkt in packets:
        if IP in pkt:
            counter[pkt[IP].src] += 1

    findings = []
    for src, count in counter.items():
        if count >= DDOS_THRESHOLD:
            findings.append({
                "rule": 2, "name": "Excessive traffic",
                "severity": _severity(count, DDOS_THRESHOLD, 1000, 5000),
                "src": src, "dst": "multiple", "protocol": "IP",
                "count": count,
                "detail": f"Source {src} sent {count} packets — possible DDoS/flood",
            })
    return findings


# ---------------------------------------------------------------------------
# Rule 3 — Packet size anomaly
# ---------------------------------------------------------------------------
def rule3_packet_size(packets) -> list:
    """
    Large packets (>1400 bytes) can indicate data exfiltration or
    amplification attacks. Tiny packets (<20 bytes) can be probes.
    """
    from scapy.layers.inet import IP
    large_by_src = defaultdict(int)
    tiny_by_src  = defaultdict(int)

    for pkt in packets:
        if IP in pkt:
            size = len(pkt)
            if size > LARGE_PACKET_BYTES:
                large_by_src[pkt[IP].src] += 1
            elif size < TINY_PACKET_BYTES:
                tiny_by_src[pkt[IP].src] += 1

    findings = []
    for src, count in large_by_src.items():
        if count > 5:
            findings.append({
                "rule": 3, "name": "Large packet anomaly",
                "severity": _severity(count, 5, 50, 200),
                "src": src, "dst": "—", "protocol": "IP",
                "count": count,
                "detail": f"{count} packets > {LARGE_PACKET_BYTES}B from {src}",
            })
    for src, count in tiny_by_src.items():
        if count > 20:
            findings.append({
                "rule": 3, "name": "Tiny packet anomaly",
                "severity": "LOW",
                "src": src, "dst": "—", "protocol": "IP",
                "count": count,
                "detail": f"{count} packets < {TINY_PACKET_BYTES}B from {src}",
            })
    return findings


# ---------------------------------------------------------------------------
# Rule 4 — Unsolicited ARP replies
# ---------------------------------------------------------------------------
def rule4_arp_replies(packets) -> list:
    """
    ARP spoofing (gratuitous ARP) sends replies without a prior request.
    We track ARP requests and flag any reply that has no matching request.
    This is a core DFIR technique covered in Lecture 4.
    """
    from scapy.layers.l2 import ARP
    requests = set()   # set of (src_mac, target_ip) pairs
    unsolicited = defaultdict(int)

    for pkt in packets:
        if ARP in pkt:
            arp = pkt[ARP]
            if arp.op == 1:   # who-has (request)
                requests.add((arp.hwsrc, arp.pdst))
            elif arp.op == 2: # is-at (reply)
                key = (arp.hwsrc, arp.psrc)
                if key not in requests:
                    unsolicited[arp.hwsrc] += 1

    findings = []
    for mac, count in unsolicited.items():
        if count > 2:
            findings.append({
                "rule": 4, "name": "Unsolicited ARP reply (possible spoofing)",
                "severity": _severity(count, 2, 10, 50),
                "src": mac, "dst": "broadcast", "protocol": "ARP",
                "count": count,
                "detail": f"MAC {mac} sent {count} ARP replies with no matching request",
            })
    return findings


# ---------------------------------------------------------------------------
# Rule 5 — Large DNS responses
# ---------------------------------------------------------------------------
def rule5_large_dns(packets) -> list:
    """
    DNS amplification attacks use large DNS responses.
    RFC 1035 limits traditional DNS to 512 bytes; anything larger
    is suspicious in most environments.
    """
    from scapy.layers.inet import IP, UDP
    from scapy.layers.dns import DNS
    large_by_src = defaultdict(int)

    for pkt in packets:
        if DNS in pkt and UDP in pkt:
            dns = pkt[DNS]
            if dns.qr == 1:  # it's a response (not a query)
                payload_len = len(pkt[DNS])
                if payload_len > LARGE_DNS_BYTES:
                    large_by_src[pkt[IP].src] += 1

    findings = []
    for src, count in large_by_src.items():
        findings.append({
            "rule": 5, "name": "Large DNS response",
            "severity": _severity(count, 1, 10, 50),
            "src": src, "dst": "—", "protocol": "DNS/UDP",
            "count": count,
            "detail": f"{count} DNS responses > {LARGE_DNS_BYTES}B from {src}",
        })
    return findings


# ---------------------------------------------------------------------------
# Rule 6 — Excessive ICMP Echo requests
# ---------------------------------------------------------------------------
def rule6_icmp_flood(packets) -> list:
    """
    ICMP Echo flood (ping flood) is a classic DoS vector.
    Flags any source exceeding ICMP_FLOOD_THRESHOLD echo requests.
    """
    from scapy.layers.inet import IP, ICMP
    counter = defaultdict(int)

    for pkt in packets:
        if ICMP in pkt and IP in pkt:
            if pkt[ICMP].type == 8:  # echo-request
                counter[pkt[IP].src] += 1

    findings = []
    for src, count in counter.items():
        if count >= ICMP_FLOOD_THRESHOLD:
            findings.append({
                "rule": 6, "name": "ICMP Echo flood",
                "severity": _severity(count, ICMP_FLOOD_THRESHOLD, 500, 2000),
                "src": src, "dst": "multiple", "protocol": "ICMP",
                "count": count,
                "detail": f"{count} ICMP echo requests from {src}",
            })
    return findings


# ---------------------------------------------------------------------------
# Rule 7 — Excessive TCP SYN (SYN flood)
# ---------------------------------------------------------------------------
def rule7_syn_flood(packets) -> list:
    """
    A SYN flood sends many SYN packets without completing the handshake
    (no ACK). We compare SYN count vs SYN-ACK/ACK count per source.
    """
    from scapy.layers.inet import IP, TCP
    syn_count   = defaultdict(int)
    synack_count = defaultdict(int)

    for pkt in packets:
        if IP in pkt and TCP in pkt:
            flags = pkt[TCP].flags
            src   = pkt[IP].src
            if flags == 0x02:  # SYN only
                syn_count[src] += 1
            elif flags in (0x12, 0x10):  # SYN-ACK or ACK
                synack_count[src] += 1

    findings = []
    for src, syns in syn_count.items():
        acks = synack_count.get(src, 0)
        incomplete = syns - acks
        if incomplete >= SYN_FLOOD_THRESHOLD:
            findings.append({
                "rule": 7, "name": "TCP SYN flood",
                "severity": _severity(incomplete, SYN_FLOOD_THRESHOLD, 500, 2000),
                "src": src, "dst": "multiple", "protocol": "TCP",
                "count": incomplete,
                "detail": f"{incomplete} unanswered SYNs from {src} (SYNs={syns}, ACKs={acks})",
            })
    return findings


# ---------------------------------------------------------------------------
# Rule 8 — IP scanning excessive ports
# ---------------------------------------------------------------------------
def rule8_port_scan(packets) -> list:
    """
    Port scanning: one source IP contacting many distinct destination ports.
    Mirrors Nmap scan behaviour observed in Lectures 32–34.
    """
    from scapy.layers.inet import IP, TCP, UDP
    # src_ip -> set of (dst_ip, dst_port) pairs
    scan_map = defaultdict(set)

    for pkt in packets:
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            if TCP in pkt:
                scan_map[src].add((dst, pkt[TCP].dport))
            elif UDP in pkt:
                scan_map[src].add((dst, pkt[UDP].dport))

    findings = []
    for src, targets in scan_map.items():
        if len(targets) >= PORT_SCAN_THRESHOLD:
            findings.append({
                "rule": 8, "name": "Port scan detected",
                "severity": _severity(len(targets), PORT_SCAN_THRESHOLD, 50, 200),
                "src": src, "dst": "multiple", "protocol": "TCP/UDP",
                "count": len(targets),
                "detail": f"{src} contacted {len(targets)} distinct (IP, port) pairs",
            })
    return findings


# ---------------------------------------------------------------------------
# Master runner — applies all 8 rules
# ---------------------------------------------------------------------------
def run_all_rules(packets) -> list:
    """
    Run all 8 rules and return a flat list of findings sorted by severity.
    """
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_findings = []
    runners = [
        rule1_common_ports,
        rule2_excessive_traffic,
        rule3_packet_size,
        rule4_arp_replies,
        rule5_large_dns,
        rule6_icmp_flood,
        rule7_syn_flood,
        rule8_port_scan,
    ]
    for fn in runners:
        try:
            all_findings.extend(fn(packets))
        except Exception as e:
            all_findings.append({
                "rule": 0, "name": f"Rule error ({fn.__name__})",
                "severity": "LOW", "src": "—", "dst": "—",
                "protocol": "—", "count": 0,
                "detail": str(e),
            })

    return sorted(all_findings, key=lambda f: severity_order.get(f["severity"], 9))
