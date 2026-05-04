"""
main.py — CLI Entry Point
--------------------------
Usage examples:
  python -m netsentinel.main --pcap capture.pcap
  python -m netsentinel.main --pcap capture.pcap --nmap --analyst "Your Name"
  sudo python -m netsentinel.main --live --iface eth0 --duration 120
"""

import argparse
import os
import sys


def parse_args():
    parser = argparse.ArgumentParser(
        prog="netsentinel",
        description="NetSentinel — Network Anomaly Detection & DFIR Reporter",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--pcap",  metavar="FILE",  help="Path to a .pcap file to analyse")
    mode.add_argument("--live",  action="store_true", help="Live packet capture mode")

    parser.add_argument("--iface",    default="eth0",      help="Interface for live capture (default: eth0)")
    parser.add_argument("--duration", type=int, default=60, help="Live capture duration in seconds (default: 60)")
    parser.add_argument("--nmap",     action="store_true",  help="Run Nmap enrichment on flagged IPs")
    parser.add_argument("--analyst",  default="Unknown",    help="Analyst name for chain-of-custody log")
    parser.add_argument("--output",   default="reports",    help="Output directory (default: reports/)")
    return parser.parse_args()


def nmap_enrich(ip_set: set) -> dict:
    """
    Run a quick Nmap scan on a set of IPs and return open ports per IP.
    Requires python-nmap and nmap binary installed.
    Mirrors Lectures 32-34 (Nmap scanning and output parsing).
    """
    try:
        import nmap
        nm = nmap.PortScanner()
        results = {}
        for ip in ip_set:
            print(f"  [nmap] Scanning {ip} ...")
            nm.scan(ip, arguments="-sV --open -T4 --top-ports 100")
            if ip in nm.all_hosts():
                ports = []
                for proto in nm[ip].all_protocols():
                    for port in nm[ip][proto].keys():
                        state = nm[ip][proto][port]["state"]
                        name  = nm[ip][proto][port].get("name", "")
                        if state == "open":
                            ports.append(f"{port}/{proto} ({name})")
                results[ip] = ports
        return results
    except ImportError:
        print("  [!] python-nmap not installed. Skipping Nmap enrichment.")
        return {}
    except Exception as e:
        print(f"  [!] Nmap error: {e}")
        return {}


def main():
    args = parse_args()

    # ── Lazy imports so the CLI starts fast ──────────────────────────────────
    from netsentinel.capture  import read_pcap, live_capture, basic_stats, save_pcap
    from netsentinel.rules    import run_all_rules
    from netsentinel.hasher   import compute_hashes, write_custody_log
    from netsentinel.reporter import generate_reports

    # ── Step 1: Acquire packets ──────────────────────────────────────────────
    if args.pcap:
        source_file = args.pcap
        packets = read_pcap(source_file)
        print("[+] Computing file hashes for chain of custody ...")
        hashes = compute_hashes(source_file)
    else:
        # Live capture: save to temp file so we can hash it
        source_file = os.path.join(args.output, "live_capture.pcap")
        os.makedirs(args.output, exist_ok=True)
        packets = live_capture(args.iface, args.duration)
        save_pcap(packets, source_file)
        hashes = compute_hashes(source_file)

    print(f"    MD5    : {hashes['md5']}")
    print(f"    SHA256 : {hashes['sha256']}")

    # ── Step 2: Run all 8 detection rules ───────────────────────────────────
    print("[+] Running anomaly detection rules ...")
    findings = run_all_rules(packets)
    print(f"    {len(findings)} anomaly(ies) found.")

    # ── Step 3: Optional Nmap enrichment ────────────────────────────────────
    if args.nmap and findings:
        print("[+] Nmap enrichment of flagged IPs ...")
        flagged_ips = {f["src"] for f in findings if "." in f.get("src", "")}
        nmap_results = nmap_enrich(flagged_ips)
        # Annotate findings with Nmap data
        for f in findings:
            if f["src"] in nmap_results:
                ports = ", ".join(nmap_results[f["src"]]) or "none"
                f["detail"] += f" | Open ports: {ports}"

    # ── Step 4: Compute summary stats ───────────────────────────────────────
    stats = basic_stats(packets)

    # ── Step 5: Write chain-of-custody log ──────────────────────────────────
    log_path = write_custody_log(source_file, hashes, args.analyst, args.output)
    print(f"[+] Chain-of-custody log: {log_path}")

    # ── Step 6: Generate HTML + JSON reports ─────────────────────────────────
    html_path, json_path = generate_reports(
        findings=findings,
        stats=stats,
        hashes=hashes,
        source_file=source_file,
        analyst=args.analyst,
        output_dir=args.output,
    )
    print(f"[+] HTML report : {html_path}")
    print(f"[+] JSON export : {json_path}")

    # ── Step 7: Terminal summary ─────────────────────────────────────────────
    print("\n" + "=" * 55)
    print("  NETSENTINEL SUMMARY")
    print("=" * 55)
    print(f"  Packets analysed : {stats['total_packets']:,}")
    print(f"  Anomalies found  : {len(findings)}")
    crit = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    print(f"  CRITICAL         : {crit}")
    print(f"  HIGH             : {high}")
    print("=" * 55)
    for f in findings:
        print(f"  [{f['severity']:<8}] Rule {f['rule']} — {f['name']}")
        print(f"             {f['detail'][:70]}")
    print("=" * 55)


if __name__ == "__main__":
    main()
