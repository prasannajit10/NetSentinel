# Debugging NetSentinel End-to-End: From "0 Anomalies Found" to a Verified Real-World Detection

**Project:** [NetSentinel](https://github.com/prasannajit10/NetSentinel) — Python CLI for network anomaly detection & DFIR reporting
**Author:** J Prasannajit
**Environment:** VirtualBox lab — Kali Linux (attacker/analysis) + Metasploitable2 (target), isolated Internal Network

---

## Problem

NetSentinel had unit tests and a working codebase on paper, but had never been validated against real network traffic. Setting it up end-to-end — from a clean VirtualBox lab to a real Nmap scan correctly triggering detections — surfaced five separate, unrelated bugs across three layers: packaging, a Scapy internals gotcha, and VM networking. Each one produced a *plausible-looking* failure that could easily have been misread as "the tool doesn't work" rather than "there's a specific, fixable cause."

## Approach

Rather than guessing, each failure was isolated and reproduced before being fixed — checking actual command output, interpreter paths, and packet captures rather than assuming the first explanation. The sections below are ordered as they were actually found.

---

## Part 1 — Code Fixes (in the NetSentinel repo)

### Fix 1: Missing package structure
**Problem:** The uploaded project had all `.py` files flat in the repo root, but `main.py` used absolute imports (`from netsentinel.capture import ...`) that only work if the code is an actual installable package.
**Fix:** Moved `capture.py`, `hasher.py`, `main.py`, `reporter.py`, `rules.py` into a `netsentinel/` subfolder with an `__init__.py`, and moved `test_rules.py` into `tests/`.

### Fix 2: Missing `dashboard.py`
**Problem:** The README described a Rich-based terminal dashboard and listed `rich` as a dependency, but `dashboard.py` didn't exist anywhere in the codebase.
**Fix:** Wrote `netsentinel/dashboard.py` — a Rich-based summary panel + severity-colored findings table, with a plain-text fallback if `rich` isn't installed. Wired it into `main.py` in place of the old manual `print()` summary.

### Fix 3: `setup.py` cleanup
**Fix:** Replaced the `"Your Name"` author placeholder, added `rich` and `pytest` to `install_requires` since they were actually used but not declared.

### Fix 4: The critical bug — Scapy silently parsing every packet as `Raw`
**Problem:** After capturing real Nmap scan traffic, NetSentinel consistently reported "0 anomalies found" — even against traffic that should have obviously tripped several rules. The console showed:
```
WARNING: PcapReader: unknown LL type [1]/[0x1]. Using Raw packets
```
**Root cause (confirmed by direct testing):** `capture.py` imported `rdpcap` via `from scapy.utils import rdpcap`. Scapy only registers its link-layer-type → protocol bindings (e.g. "linktype 1 means Ethernet, parse as Ether/IP/TCP") as a side effect of importing the full `scapy.all` module. Importing just `scapy.utils.rdpcap` skips that registration entirely, so Scapy had no idea linktype 1 was Ethernet and silently fell back to unparsed `Raw` packets — meaning every detection rule (which all expect parsed `IP`/`TCP`/`ICMP` layers) had nothing to work with, regardless of what was actually in the capture.
**Fix:**
```python
# Before:
from scapy.utils import rdpcap

# After:
from scapy.all import rdpcap
```
Verified with a controlled test: identical packets, before the fix → `Raw`, `0 findings`; after the fix → correctly parsed `Ether/IP/TCP`, rules fired as expected.

---

## Part 2 — Lab Environment Fixes (VirtualBox / networking)

### Issue 1: Wrong VirtualBox dialog for importing Metasploitable2
Metasploitable2 ships as loose VMware files (`.vmdk`, `.vmx`, etc.), not a `.vbox`/`.ova`. Using VirtualBox's **Add** (existing machine) option fails silently ("No items match your search") because it only accepts `.xml`/`.vbox`. Fix: use **New → Use an Existing Virtual Hard Disk File**, and point it at the `.vmdk` directly.

### Issue 2: No internet access inside Kali (DNS failures on `apt-get`)
Kali's only network adapter was set to **Internal Network** (correct for the isolated lab), which by design has zero route to the internet — breaking `apt-get`/`pip`. Fix: added a **second adapter** (Adapter 2) set to **NAT**, giving Kali internet access on a separate interface while Adapter 1 stayed isolated for the lab.

### Issue 3: `pytest` picking up the wrong Python interpreter
Tests failed with `ModuleNotFoundError: No module named 'netsentinel'` even with the venv active and the package installed via `pip install -e .`. Root cause: Kali also has a system-wide `pytest` (from `apt`) earlier in `PATH` than the venv's version. Fix: invoke via `python -m pytest ...` instead of bare `pytest ...`, forcing use of the venv's interpreter.

### Issue 4: `kill %1` failing under `sudo`
`%1` job-number syntax is a **bash builtin** feature — it only works when bash itself parses it. `sudo kill %1` sends `%1` literally to the real `kill` binary, which doesn't understand it. Fix: use `sudo pkill tcpdump` (kill by process name) instead of job-number syntax.

### Issue 5: `tcpdump` and `nmap` running in separate terminals, badly out of sync
Manually switching between a `tcpdump` tab and an `nmap` tab led to captures with 0–10 packets — the two were never actually running at the same time. Fix: chain both in a single shell command so they're guaranteed to overlap:
```bash
sudo tcpdump -i eth0 -w /home/kali/lab_capture.pcap & sleep 2; nmap -sS 192.168.100.10; sudo pkill tcpdump
```

### Issue 6: `~` resolving to the wrong home directory under `sudo su`
After switching to a root shell with `sudo su`, `~/lab_capture.pcap` resolved to `/root/lab_capture.pcap` — a different file from the `/home/kali/lab_capture.pcap` being analyzed. Fix: always use an explicit absolute path in capture commands, regardless of which user runs them.

### Issue 7: NetworkManager silently flushing the static IP on `eth0`
Even after correctly assigning a static IP to Kali's lab interface, scans against the target intermittently failed or captured no traffic. `nmcli device status` showed `eth0` as **disconnected**, and the capture was full of repeating DHCP broadcast requests — NetworkManager was continuously retrying DHCP on `eth0` in the background, flushing the manually-assigned static address each cycle. Fix:
```bash
sudo nmcli device set eth0 managed no
sudo ip addr flush dev eth0
sudo ip addr add 192.168.100.20/24 dev eth0
sudo ip link set eth0 up
```
This stopped NetworkManager from touching `eth0` at all, and the static IP held permanently after that.

---

## Command Reference (in order used)

**Hypervisor / VM setup**
```bash
# VirtualBox: New VM → Use an Existing Virtual Hard Disk File → select Metasploitable.vmdk
```

**Kali — Python environment**
```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-venv git
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
python -m pytest tests/ -v
```

**Networking — isolated lab setup**
```bash
# Metasploitable2:
sudo ifconfig eth0 192.168.100.10 netmask 255.255.255.0 up

# Kali:
sudo ip addr add 192.168.100.20/24 dev eth0
sudo ip link set eth0 up
ping -c 4 192.168.100.10
```

**Networking — fixing NetworkManager interference**
```bash
nmcli device status
sudo nmcli device set eth0 managed no
sudo ip addr flush dev eth0
sudo ip addr add 192.168.100.20/24 dev eth0
sudo ip link set eth0 up
ip a show eth0
```

**Capturing and analyzing real traffic**
```bash
sudo tcpdump -i eth0 -w /home/kali/lab_capture.pcap & sleep 2; nmap -sS 192.168.100.10; sudo pkill tcpdump
tcpdump -r /home/kali/lab_capture.pcap
python -m netsentinel.main --pcap /home/kali/lab_capture.pcap --analyst "J Prasannajit"
```

---

## Result

Final run against a real `nmap -sS` SYN scan of Metasploitable2 (1,773 packets captured, 0 dropped by kernel):

| Severity | Rule | Detail |
|---|---|---|
| CRITICAL | R1 — Uncommon destination port | 875 packets to non-standard port 54191/TCP |
| CRITICAL | R8 — Port scan detected | 192.168.100.20 contacted 876 distinct (IP, port) pairs |
| HIGH | R7 — TCP SYN flood | 876 unanswered SYNs from 192.168.100.20 |
| MEDIUM | R2 — Excessive traffic | 896 packets from 192.168.100.20 |
| MEDIUM | R2 — Excessive traffic | 875 packets from 192.168.100.10 |

The port-scan finding (876 distinct pairs) lines up almost exactly with Nmap's own ~1,000-port default scan range — confirming the detection is accurate, not a false positive.

## What I Learned

- A "no results" failure in a security tool is not the same as "nothing happened" — it's worth distrusting silence and verifying with a controlled, known-bad input before trusting a clean result.
- Python's import system has sharp edges: `from module.submodule import X` vs `from module import X` can silently change what side-effect registrations happen, even when both technically "work" without erroring.
- A proper attacker/target lab needs **two NICs on the attacker box** — one isolated for the target range, one for internet/tooling — and static IP configuration on Linux isn't safe from being silently undone by NetworkManager unless the interface is explicitly unmanaged.
- Debugging methodically (confirm the interpreter, confirm the file path, confirm the packet count, confirm the interface) found every issue faster than guessing at fixes would have.

## Next Steps

- Push these fixes to the GitHub repo
- Begin converting the 8 hardcoded detection rules into a config-driven rule engine (YAML/JSON-defined thresholds)
