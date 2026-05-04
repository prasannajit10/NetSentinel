"""
capture.py — PCAP Reader + Live Sniffer
-----------------------------------------
Two modes:
  1. read_pcap(path)   — load packets from a saved .pcap file using Scapy
  2. live_capture(...) — sniff live traffic on a network interface

Mirrors Lecture 40 (Scapy library) and Assignments 8-9 (network traffic analysis).
"""

import sys


def read_pcap(filepath: str) -> list:
    """
    Read a PCAP file and return a list of Scapy packet objects.

    Scapy's rdpcap() loads the entire file. For very large captures
    (>500 MB) consider using PcapReader as a streaming iterator instead.
    """
    try:
        from scapy.utils import rdpcap
        packets = rdpcap(filepath)
        print(f"[+] Loaded {len(packets)} packets from {filepath}")
        return list(packets)
    except FileNotFoundError:
        print(f"[!] File not found: {filepath}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Failed to read PCAP: {e}")
        sys.exit(1)


def live_capture(iface: str, duration: int = 60, packet_count: int = 0) -> list:
    """
    Sniff live packets on `iface` for `duration` seconds (or `packet_count`
    packets if specified). Returns a list of Scapy packet objects.

    Requires root/admin privileges.

    Parameters
    ----------
    iface        : Network interface name, e.g. 'eth0', 'wlan0'
    duration     : How many seconds to capture (default 60)
    packet_count : If > 0, stop after this many packets regardless of time
    """
    try:
        from scapy.all import sniff
        print(f"[+] Live capture on {iface} for {duration}s ...")
        print("    Press Ctrl+C to stop early.")

        packets = sniff(
            iface=iface,
            timeout=duration,
            count=packet_count if packet_count > 0 else 0,
            store=True,
        )
        print(f"[+] Captured {len(packets)} packets.")
        return list(packets)

    except PermissionError:
        print("[!] Live capture requires root privileges. Run with sudo.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Capture error: {e}")
        sys.exit(1)


def save_pcap(packets: list, output_path: str) -> None:
    """Save a list of packets to a PCAP file (useful after live capture)."""
    from scapy.utils import wrpcap
    wrpcap(output_path, packets)
    print(f"[+] Packets saved to {output_path}")


def basic_stats(packets: list) -> dict:
    """
    Compute summary statistics from the packet list.
    Returns a dict suitable for embedding in reports.
    """
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS
    from scapy.layers.l2 import ARP
    from collections import Counter

    total = len(packets)
    protocol_counts = Counter()
    src_ips = Counter()

    for pkt in packets:
        if IP in pkt:
            src_ips[pkt[IP].src] += 1
            if TCP in pkt:   protocol_counts["TCP"] += 1
            elif UDP in pkt: protocol_counts["UDP"] += 1
            elif ICMP in pkt: protocol_counts["ICMP"] += 1
            else:             protocol_counts["Other IP"] += 1
        elif ARP in pkt:
            protocol_counts["ARP"] += 1
        else:
            protocol_counts["Non-IP"] += 1

        if DNS in pkt:
            protocol_counts["DNS"] += 1

    return {
        "total_packets": total,
        "protocol_breakdown": dict(protocol_counts),
        "top_talkers": src_ips.most_common(10),
    }
