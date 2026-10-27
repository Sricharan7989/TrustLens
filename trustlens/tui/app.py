"""TrustLens Terminal GUI (OpenCode / TUI).
Provides an interactive, luxury terminal GUI experience powered by Rich.
Scans local packages, benchmark toys, or live PyPI packages, displays XGBoost Threat Scores,
behavioral claims disparity, and Gemini LLM forensic reports directly in the terminal.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any

from rich.align import Align
from rich.box import DOUBLE, ROUNDED, SIMPLE
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from trustlens.claims.extract import extract_claims, read_package_info
from trustlens.cli import scan
from trustlens.llm.reporter import generate_llm_report
from trustlens.ml.threat_model import get_threat_model
from trustlens.resolver import resolve_package
from trustlens.static.ast_analyzer import scan_package_static

console = Console()

BANNER = """[bold white]
  ████████╗██████╗ ██╗   ██╗███████╗████████╗██╗     ███████╗███╗   ██╗███████╗
  ╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝██║     ██╔════╝████╗  ██║██╔════╝
     ██║   ██████╔╝██║   ██║███████╗   ██║   ██║     █████╗  ██╔██╗ ██║███████╗
     ██║   ██╔══██╗██║   ██║╚════██║   ██║   ██║     ██╔══╝  ██║╚██╗██║╚════██║
     ██║   ██║  ██║╚██████╔╝███████║   ██║   ███████╗███████╗██║ ╚████║███████║
     ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝[/bold white]
[bold bright_black]  ◈ BEHAVIORAL PROVENANCE & SUPPLY CHAIN INTELLIGENCE ENGINE ◈[/bold bright_black]"""


def render_header() -> Panel:
    header_text = Text()
    header_text.append("TrustLens AI  ", style="bold white")
    header_text.append("│  ", style="bright_black")
    header_text.append("ML Engine: ", style="dim white")
    header_text.append("XGBoost v3.2  ", style="bold cyan")
    header_text.append("│  ", style="bright_black")
    header_text.append("LLM: ", style="dim white")
    header_text.append("Gemini 3.8 Flash  ", style="bold magenta")
    header_text.append("│  ", style="bright_black")
    header_text.append("Sandbox: ", style="dim white")
    header_text.append("Bubblewrap & AST Hybrid", style="bold green")
    return Panel(Align.center(header_text), box=ROUNDED, border_style="bright_black", style="on #080808")


def render_threat_gauge(score: float, tier: str) -> Text:
    total_bars = 24
    filled = int(round((score / 100.0) * total_bars))
    filled = max(0, min(total_bars, filled))
    empty = total_bars - filled

    gauge = Text()
    gauge.append("[", style="bright_black")

    color = "bright_green"
    if score >= 80.0 or tier == "CRITICAL":
        color = "bold bright_red"
    elif score >= 60.0 or tier == "HIGH":
        color = "bold red"
    elif score >= 35.0 or tier == "MEDIUM":
        color = "bold yellow"
    elif score >= 12.0 or tier == "LOW":
        color = "bright_cyan"

    gauge.append("█" * filled, style=color)
    gauge.append("░" * empty, style="bright_black")
    gauge.append("] ", style="bright_black")
    gauge.append(f"{score:.1f} / 100.0", style=f"bold {color}")
    gauge.append(f"  [{tier} RISK]", style=f"bold on {color}" if tier in ("CRITICAL", "HIGH") else f"bold {color}")
    return gauge


def execute_full_scan(target_query: str, verbose: bool = False) -> dict:
    """Execute complete TrustLens scan on any target: PyPI name, toy ID, or local directory."""
    with Progress(
        SpinnerColumn(style="bold magenta"),
        TextColumn("[bold white]{task.description}"),
        BarColumn(bar_width=30, style="bright_black", complete_style="bold magenta"),
        console=console,
        transient=True,
    ) as prog:
        t_resolve = prog.add_task("[1/5] Retrieving package artifacts & metadata...", total=100)
        time.sleep(0.15)
        resolved = resolve_package(target_query)
        prog.update(t_resolve, completed=100)

        t_claims = prog.add_task("[2/5] Parsing README & extracting declared capability claims...", total=100)
        time.sleep(0.15)
        pkg_root = resolved.local_path
        claims = extract_claims(str(pkg_root))
        prog.update(t_claims, completed=100)

        t_inspect = prog.add_task("[3/5] Tracking behavioral code execution & static AST patterns...", total=100)
        time.sleep(0.15)
        static_res = scan_package_static(pkg_root)

        # Run core scan engine
        out_dir = Path("reports") / resolved.name
        scan_res = scan(
            str(pkg_root),
            str(out_dir),
            runner="auto",
            profiles=("dev", "ci"),
            offline=True,
            static=False,
        )
        verdict = scan_res["verdict"]
        fingerprint = scan_res["fingerprint"]
        prog.update(t_inspect, completed=100)

        t_ml = prog.add_task("[4/5] Scoring threat probabilities via XGBoost model...", total=100)
        time.sleep(0.15)
        tm = get_threat_model()
        prediction = tm.predict(verdict, fingerprint, claims, static_res)
        prog.update(t_ml, completed=100)

        t_llm = prog.add_task("[5/5] Synthesizing Executive Intelligence Report with Gemini...", total=100)
        llm_res = generate_llm_report(verdict, fingerprint, claims, prediction)
        prog.update(t_llm, completed=100)

    return {
        "resolved": resolved,
        "claims": claims,
        "static": static_res,
        "scan": scan_res,
        "verdict": verdict,
        "fingerprint": fingerprint,
        "prediction": prediction,
        "llm_report": llm_res,
        "out_dir": str(out_dir),
    }


def display_terminal_report(scan_data: dict):
    resolved = scan_data["resolved"]
    verdict = scan_data["verdict"]
    claims = scan_data["claims"]
    pred = scan_data["prediction"]
    llm = scan_data["llm_report"]
    findings = verdict.get("findings") or []

    action = verdict.get("action", "REVIEW")
    verdict_name = verdict.get("verdict", "INCONCLUSIVE")

    # 1. Action Verdict Banner
    if action == "BLOCK":
        v_color = "bold bright_red"
        v_border = "bright_red"
        v_title = "⛔ [ACTION: BLOCK] — MALICIOUS ACTIVITY DETECTED"
    elif action == "PASS":
        v_color = "bold bright_green"
        v_border = "bright_green"
        v_title = "🛡️ [ACTION: PASS] — BENIGN CONSISTENT"
    else:
        v_color = "bold bright_yellow"
        v_border = "bright_yellow"
        v_title = f"⚠️ [ACTION: {action}] — {verdict_name}"

    banner_panel = Panel(
        Align.center(Text(v_title, style=v_color)),
        box=ROUNDED,
        border_style=v_border,
        style="on #0c0505" if action == "BLOCK" else "on #050c05" if action == "PASS" else "on #0c0c05",
    )
    console.print()
    console.print(banner_panel)

    # 2. Package Identity & XGBoost Threat Metrics (2-column layout)
    info_table = Table(box=SIMPLE, show_header=False, padding=(0, 1))
    info_table.add_column("Key", style="dim white")
    info_table.add_column("Value", style="bold white")

    info_table.add_row("Package Name", f"[bold cyan]{resolved.name}[/bold cyan]")
    info_table.add_row("Version", f"{resolved.version}")
    info_table.add_row("Source", f"{resolved.source_type.upper()}")
    info_table.add_row("SHA256", f"[bright_black]{verdict.get('package', {}).get('sha256', 'unknown')[:24]}...[/bright_black]")
    intents = [i.get("intent") for i in claims.get("intents", [])]
    info_table.add_row("README Intent", f"{', '.join(intents) or 'None / Undeclared'}")

    # Right side: XGBoost Score & Top Factors
    ml_content = Text()
    ml_content.append("XGBoost Threat Score:\n", style="bold white")
    ml_content.append_text(render_threat_gauge(pred.threat_score, pred.risk_tier))
    ml_content.append("\n\nPrimary Risk Signals:\n", style="bold white")
    if pred.top_factors:
        for tf in pred.top_factors[:3]:
            ml_content.append(f" • {tf['factor']} ", style="white")
            ml_content.append(f"({tf['weight']})\n", style="bold red" if "+" in tf['weight'] else "bold green")
    else:
        ml_content.append(" • Zero malicious indicators detected\n", style="green")

    grid = Table.grid(expand=True)
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)
    grid.add_row(
        Panel(info_table, title="[bold white]Package Provenance[/bold white]", box=ROUNDED, border_style="bright_black"),
        Panel(ml_content, title="[bold white]Machine Learning Scoring[/bold white]", box=ROUNDED, border_style=v_border),
    )
    console.print(grid)

    # 3. LLM Executive Intelligence Report
    llm_header = f"[bold magenta]⚡ {llm.model_used}[/bold magenta]"
    console.print(
        Panel(
            Markdown(llm.report_markdown),
            title=f"[bold white]Executive Threat Intelligence Report[/bold white] — {llm_header}",
            box=ROUNDED,
            border_style="magenta",
            padding=(1, 2),
        )
    )

    # 4. Forensic Findings Table
    if findings:
        f_table = Table(
            title="[bold white]Observed Forensic Events & Rule Triggers[/bold white]",
            box=ROUNDED,
            border_style="bright_black",
            header_style="bold cyan",
            expand=True,
        )
        f_table.add_column("Severity", justify="center", width=10)
        f_table.add_column("Rule Trigger", width=22)
        f_table.add_column("Capability", width=18)
        f_table.add_column("Phase", width=10)
        f_table.add_column("Forensic Detail", style="dim white")

        for f in findings:
            sev = f.get("severity", "medium").upper()
            sev_style = "bold bright_red" if sev == "CRITICAL" else "bold red" if sev == "HIGH" else "yellow"
            detail = ""
            for ev in f.get("evidence", []):
                d = ev.get("detail", {})
                detail = str(d.get("path") or d.get("dest") or d.get("url") or d.get("file") or "")
                break
            f_table.add_row(
                Text(sev, style=sev_style),
                f.get("rule", "unknown"),
                f.get("capability", "unspecified"),
                ", ".join(f.get("phases", [])),
                detail or f.get("title", ""),
            )
        console.print(f_table)
    else:
        console.print(
            Panel(
                "[bold green]✔ Zero anomalous or untracked behavioral operations observed.[/bold green]",
                box=ROUNDED,
                border_style="bright_black",
            )
        )

    console.print(f"[dim white]  Artifacts saved: [bold cyan]{scan_data['out_dir']}/report.html[/bold cyan][/dim white]\n")


def launch_tui():
    """Interactive loop for TrustLens Terminal UI."""
    console.clear()
    console.print(BANNER)
    console.print(render_header())
    console.print()

    while True:
        console.print("[bold white]Ready to inspect dependencies.[/bold white] Select a benchmark toy or enter any PyPI package:")
        console.print("  [bold cyan][1][/bold cyan] evil_slug      (malicious: credential exfil)")
        console.print("  [bold cyan][2][/bold cyan] clean_slug     (clean: string utility)")
        console.print("  [bold cyan][3][/bold cyan] rest_wrapper   (noisy-benign: declared REST client)")
        console.print("  [bold cyan][4][/bold cyan] delayed_slug   (malicious: CI-gated exfil)")
        console.print("  [bold cyan][5][/bold cyan] pth_hook       (malicious: interpreter startup hook)")
        console.print("  [bold cyan][q][/bold cyan] Quit")
        console.print()

        choice = Prompt.ask(
            "[bold white]TrustLens[/bold white] [bold cyan]❯[/bold cyan]",
            default="requests",
        ).strip()

        if choice.lower() in ("q", "quit", "exit"):
            console.print("[dim white]Exiting TrustLens. Stay secure.[/dim white]")
            break

        # Map shortcut numbers
        shortcut_map = {
            "1": "evil_slug",
            "2": "clean_slug",
            "3": "rest_wrapper",
            "4": "delayed_slug",
            "5": "pth_hook",
        }
        target = shortcut_map.get(choice, choice)

        console.print(f"\n[bold white]Initializing scan for:[/bold white] [bold cyan]{target}[/bold cyan]...")
        try:
            scan_data = execute_full_scan(target)
            display_terminal_report(scan_data)
        except Exception as e:
            console.print(f"\n[bold red]Scan Error:[/bold red] {e}\n")

        # Post scan action prompt
        action = Prompt.ask(
            "[dim white]Press Enter to continue, 'w' to view web report, or 'q' to quit[/dim white]",
            default="",
        ).strip().lower()

        if action == "w":
            out_file = Path(scan_data["out_dir"]) / "report.html"
            console.print(f"[bold cyan]Report URL:[/bold cyan] file://{out_file.resolve()}")
            import webbrowser
            webbrowser.open(f"file://{out_file.resolve()}")
        elif action == "q":
            break
        console.print("\n" + "─" * 80 + "\n")
