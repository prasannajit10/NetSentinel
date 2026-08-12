"""
hasher.py — DFIR Chain of Custody
----------------------------------
Computes MD5 and SHA256 of the input PCAP file and logs a chain-of-custody
record. This mirrors Lecture 4 (Incident Response, Hashing, DFIR Chain of
Custody) and Lecture 5 (Hash Commands: MD5, SHA256 in Python).
"""

import hashlib
import os
from datetime import datetime, timezone


def compute_hashes(filepath: str) -> dict:
    """
    Read a file in chunks and compute MD5 + SHA256 simultaneously.
    Chunked reading avoids loading huge PCAPs into RAM at once.

    Returns a dict with keys: md5, sha256, file_size_bytes.
    """
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    size = 0

    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha256.update(chunk)
            size += len(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha256": sha256.hexdigest(),
        "file_size_bytes": size,
    }


def write_custody_log(filepath: str, hashes: dict, analyst: str, output_dir: str) -> str:
    """
    Write a plain-text chain-of-custody log.
    Returns the path of the written log file.
    """
    os.makedirs(output_dir, exist_ok=True)
    log_path = os.path.join(output_dir, "chain_of_custody.log")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        "=" * 60,
        "      NETSENTINEL — DFIR CHAIN OF CUSTODY LOG",
        "=" * 60,
        f"File        : {os.path.abspath(filepath)}",
        f"Size        : {hashes['file_size_bytes']:,} bytes",
        f"MD5         : {hashes['md5']}",
        f"SHA256      : {hashes['sha256']}",
        f"Analysed at : {timestamp}",
        f"Analyst     : {analyst}",
        "Tool        : NetSentinel v1.0",
        "=" * 60,
    ]

    with open(log_path, "w") as f:
        f.write("\n".join(lines))

    return log_path
