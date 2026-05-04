# 🛡️ NetSentinel — Automated Network Anomaly Detection & Forensics Reporter

> A Python-based network forensics tool that captures/reads PCAP files, applies 8 detection rules inspired by real SOC playbooks, computes file hashes for DFIR chain of custody, and generates a full HTML + JSON investigation report.

---

## 📌 Why This Project?

Built from hands-on coursework in **Digital Forensics (CSE3156)** and **Penetration Testing (PTW)**, this tool consolidates skills in:

- **Scapy** – packet capture and analysis (Lec 40, Assignment 19)
- **Nmap / python-nmap** – port scanning and host discovery (Lec 32–34)
- **Hashing (MD5/SHA256)** – DFIR chain of custody (Lec 4–5)
- **Network traffic analysis** – p0f-style observations (Lec 18, Assignment 8–9)
- **Netdiscover concepts** – MAC/vendor identification (Lec 30–31)
- **Wireshark-aligned rules** – protocol anomaly detection (Lec 37–39)
- **SOC/SIEM-ready output** – JSON export compatible with log aggregators

---

## 🚀 Features

| Feature | Description |
|---|---|
| PCAP analysis | Read existing `.pcap` files via Scapy |
| Live capture | Sniff live traffic on any interface |
| 8 detection rules | DDoS, ARP spoof, SYN flood, DNS amp, port scan, ICMP flood, large packets, excess traffic |
| MD5 / SHA256 hashing | Hash input PCAP for DFIR chain of custody |
| HTML report | Colour-coded, human-readable investigation report |
| JSON export | SIEM-ingestible structured findings |
| Terminal dashboard | Rich-formatted live summary |
| Nmap integration | Optional host/port enrichment of flagged IPs |

---

## 🗂️ Project Structure

```
netsentinel/
├── netsentinel/
│   ├── __init__.py
│   ├── capture.py      # PCAP reader + live sniffer
│   ├── rules.py        # 8 anomaly detection rules
│   ├── hasher.py       # MD5/SHA256 + chain-of-custody log
│   ├── reporter.py     # HTML + JSON report generator
│   ├── dashboard.py    # Terminal dashboard (Rich)
│   └── main.py         # CLI entry point
├── tests/
│   ├── test_rules.py   # Unit tests for each rule
├── sample_data/        # Put your .pcap files here
├── reports/            # Auto-generated reports land here
├── requirements.txt
├── setup.py
└── README.md
```

---

## ⚙️ Installation

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/netsentinel.git
cd netsentinel

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

> **Note:** Live packet capture requires root/admin privileges.

---

## 🖥️ Usage

### Analyse a PCAP file
```bash
python -m netsentinel.main --pcap sample_data/capture.pcap
```

### Live capture (5 minutes, interface eth0)
```bash
sudo python -m netsentinel.main --live --iface eth0 --duration 300
```

### With Nmap enrichment of suspicious IPs
```bash
python -m netsentinel.main --pcap sample_data/capture.pcap --nmap
```

### Custom output directory
```bash
python -m netsentinel.main --pcap sample_data/capture.pcap --output reports/investigation_01
```

---

## 🔍 Detection Rules

All 8 rules directly mirror the anomaly categories from the Digital Forensics mini-project (Assignment 19):

| Rule | Name | What it flags |
|---|---|---|
| R1 | Common destination ports | TCP/UDP to non-standard ports (not 80, 443, 22, 53) |
| R2 | Excessive traffic (DDoS) | Any single source sending > 500 packets/min |
| R3 | Packet size anomaly | Packets > 1400 bytes or suspiciously tiny (< 20 bytes) |
| R4 | Unsolicited ARP replies | ARP replies without a corresponding request |
| R5 | Large DNS responses | DNS response payload > 512 bytes |
| R6 | ICMP echo flood | > 100 ICMP echo requests from one source |
| R7 | Excessive TCP SYN | > 200 SYN packets from one source without ACK |
| R8 | IP port scanning | One IP hitting > 20 distinct destination ports |

Each finding includes: source IP, destination IP, protocol, count, severity (LOW/MEDIUM/HIGH/CRITICAL), and a plain-English description.

---

## 📊 Sample Output

```
╔══════════════════════════════════════════╗
║        NetSentinel Investigation         ║
║   Packets analysed : 12,450              ║
║   Anomalies found  : 7                   ║
║   Severity CRITICAL: 2                   ║
╚══════════════════════════════════════════╝

[CRITICAL] TCP SYN Flood  — 192.168.1.44 → multiple (1,203 SYNs, no ACK)
[HIGH]     ARP Spoofing   — 00:1A:2B:3C:4D:5E (unsolicited replies: 87)
[HIGH]     Port Scan      — 10.0.0.5 touched 34 distinct ports
[MEDIUM]   DNS Amplify    — Response 2048 bytes from 8.8.8.8
[LOW]      Large Packets  — 12 packets > 1400 bytes
```

---

## 🔐 DFIR Chain of Custody

Every analysis run produces a `chain_of_custody.log`:

```
File        : capture.pcap
MD5         : d41d8cd98f00b204e9800998ecf8427e
SHA256      : e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Analysed at : 2024-12-01 14:32:11 UTC
Analyst     : [your name]
Tool        : NetSentinel v1.0
```

This follows the DFIR Chain of Custody (CoC) principles from Lecture 4.

---

## 📈 Scalability Roadmap

This project is designed to grow. Planned extensions:

- [ ] **v1.1** – Volatility3 integration: cross-reference suspicious IPs with memory dumps
- [ ] **v1.2** – Autopsy plugin: export findings as Autopsy-compatible case file
- [ ] **v1.3** – Real-time dashboard with WebSocket streaming
- [ ] **v1.4** – Machine learning baseline (detect anomalies vs. normal traffic profile)
- [ ] **v1.5** – Shodan API integration to enrich flagged public IPs

---

## 🛠️ Technologies Used

| Technology | Purpose | Learned in |
|---|---|---|
| Scapy | Packet parsing and capture | Lec 40, Assignment 19 |
| python-nmap | Host/port enrichment | Lec 32–34 |
| Jinja2 | HTML report templating | — |
| Rich | Terminal dashboard | — |
| hashlib | MD5/SHA256 hashing | Lec 4–5 |
| argparse | CLI interface | — |
| pytest | Unit testing | — |

---

## 📚 References

- Digital Forensics with Kali Linux (2nd Ed.) – Shiva V. N. Parasram, Packt
- Course: CSE3156 Digital Forensics, 2024–25
- Scapy documentation: https://scapy.readthedocs.io
- Wireshark protocol analysis: Lectures 37–39

---

## 👤 Author

**[Your Name]** — B.Tech CSE, [Your College]  
Course: CSE3156 Digital Forensics | PTW Penetration Testing  
GitHub: [@YOUR_USERNAME](https://github.com/YOUR_USERNAME)

---

## 📄 License

MIT License — free to use, modify, and distribute.
