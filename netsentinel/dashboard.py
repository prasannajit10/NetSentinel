"""
dashboard.py — Rich Terminal Dashboard
-----------------------------------------
Renders a colour-coded summary of a NetSentinel run directly in the
terminal using the `rich` library. This was referenced in the README's
feature list and project structure but was never actually implemented —
this file fills that gap.

Falls back to a plain-text summary if `rich` isn't installed, so the
tool never hard-depends on it.
"""


def render_dashboard(stats: dict, findings: list, hashes: dict, source_file: str) -> None:
    """
    Print a Rich-formatted dashboard: summary stats panel + a findings
    table colour-coded by severity. Degrades gracefully to plain text
    if `rich` is unavailable.
    """
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich.text import Text
    except ImportError:
        _plain_fallback(stats, findings, hashes, source_file)
        return

    console = Console()

    severity_style = {
        "CRITICAL": "bold white on red",
        "HIGH": "bold black on dark_orange",
        "MEDIUM": "bold black on yellow",
        "LOW": "bold white on green",
    }

    crit = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    med  = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low  = sum(1 for f in findings if f["severity"] == "LOW")

    summary = (
        f"[bold]Source file[/bold]   : {source_file}\n"
        f"[bold]Packets analysed[/bold] : {stats['total_packets']:,}\n"
        f"[bold]Anomalies found[/bold]  : {len(findings)}\n"
        f"[bold]SHA256[/bold]  : {hashes.get('sha256', '—')}\n"
        f"[red]CRITICAL: {crit}[/red]  [dark_orange]HIGH: {high}[/dark_orange]  "
        f"[yellow]MEDIUM: {med}[/yellow]  [green]LOW: {low}[/green]"
    )
    console.print(Panel(summary, title="🛡️  NetSentinel Investigation", border_style="cyan"))

    if not findings:
        console.print("[green]✅ No anomalies detected.[/green]")
        return

    table = Table(show_lines=False, expand=True)
    table.add_column("Sev", justify="center", width=9)
    table.add_column("Rule")
    table.add_column("Detail", overflow="fold")
    table.add_column("Src")
    table.add_column("Count", justify="right")

    for f in findings:
        style = severity_style.get(f["severity"], "")
        table.add_row(
            Text(f["severity"], style=style),
            f"R{f['rule']} — {f['name']}",
            f["detail"],
            str(f["src"]),
            str(f["count"]),
        )

    console.print(table)


def _plain_fallback(stats: dict, findings: list, hashes: dict, source_file: str) -> None:
    """Plain-text dashboard used when `rich` is not installed."""
    print("=" * 55)
    print("  NETSENTINEL SUMMARY")
    print("=" * 55)
    print(f"  Source file      : {source_file}")
    print(f"  Packets analysed : {stats['total_packets']:,}")
    print(f"  Anomalies found  : {len(findings)}")
    print(f"  SHA256           : {hashes.get('sha256', '—')}")
    print("=" * 55)
    for f in findings:
        print(f"  [{f['severity']:<8}] Rule {f['rule']} — {f['name']}")
        print(f"             {f['detail'][:70]}")
    print("=" * 55)
