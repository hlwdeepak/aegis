from __future__ import annotations
import sys
import argparse
import uvicorn
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from aegis.models.signal import Signal, Severity
from aegis.graph.entity_graph import EntityGraph
from aegis.collectors.live_process import LiveProcessCollector
from aegis.collectors.live_network import LiveNetworkCollector
from aegis.collectors.live_persistence import LivePersistenceCollector
from aegis.collectors.synthetic_attack import generate_scenario_signals
from aegis.engine.rules import run_rules
from aegis.engine.scoring import generate_executive_metrics, entity_risk_score

console = Console()

BANNER = """[bold cyan]
     █████╗ ███████╗ ██████╗ ██╗███████╗    ██╗  ██╗
    ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝    ╚██╗██╔╝
    ███████║█████╗  ██║  ███╗██║███████╗     ╚███╔╝ 
    ██╔══██║██╔══╝  ██║   ██║██║╚════██║     ██╔██╗ 
    ██║  ██║███████╗╚██████╔╝██║███████║    ██╔╝ ██╗
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝    ╚═╝  ╚═╝[/bold cyan]
    [dim]Autonomous Endpoint Detection, Response & Threat Correlation Platform[/dim]
"""


def cli_scan(mode: str = "hybrid", scenario: str = "all_threats"):
    console.print(BANNER)
    console.print(f"[bold yellow]❯ Initializing Telemetry Collectors (Mode: {mode.upper()})...[/bold yellow]")

    graph = EntityGraph()
    signals: list[Signal] = []

    # Live collectors
    if mode in ["live", "hybrid"]:
        with console.status("[cyan]Harvesting live OS process tree, network sockets, and LaunchAgents...", spinner="dots"):
            p_col = LiveProcessCollector(sample_limit=70)
            n_col = LiveNetworkCollector()
            pers_col = LivePersistenceCollector()

            signals.extend(p_col.collect())
            signals.extend(n_col.collect())
            signals.extend(pers_col.collect())

    # Simulation signals
    if mode in ["simulation", "hybrid"]:
        sim_signals = generate_scenario_signals(scenario)
        signals.extend(sim_signals)

    for s in signals:
        graph.add_signal(s)

    # Correlate
    with console.status("[magenta]Evaluating declarative MITRE ATT&CK correlation rules...", spinner="bouncingBar"):
        incidents = run_rules(graph)
        metrics = generate_executive_metrics(graph, incidents)

    # Executive Scoreboard
    score = metrics["score"]
    score_color = "green" if score >= 80 else ("yellow" if score >= 50 else "red")
    score_panel = Panel(
        f"[bold {score_color}]POSTURE SCORE: {score}/100[/bold {score_color}]  |  [bold]{metrics['posture_tier']}[/bold]\n"
        f"Entities Analyzed: [cyan]{metrics['entity_count']}[/cyan]  |  Signals Correlated: [cyan]{metrics['total_signals']}[/cyan]  |  Active Incidents: [bold red]{len(incidents)}[/bold red]",
        title="[bold white]Executive Defense Summary[/bold white]",
        box=box.DOUBLE,
    )
    console.print(score_panel)

    # Category Table
    cat_table = Table(title="Security Domain Posture", box=box.ROUNDED)
    cat_table.add_column("Domain Category", style="cyan")
    cat_table.add_column("Threat Status", justify="center")

    for cat_name, status_dict in metrics["categories"].items():
        cat_table.add_row(cat_name, f"[{status_dict['color']}]{status_dict['badge']}[/{status_dict['color']}]")
    console.print(cat_table)

    # Incidents Table
    if incidents:
        console.print(f"\n[bold red]🚨 DETECTED CORRELATED INCIDENTS ({len(incidents)}):[/bold red]")
        for i, inc in enumerate(incidents, 1):
            sev_color = "red" if inc.severity == Severity.CRITICAL else ("bright_red" if inc.severity == Severity.HIGH else "yellow")
            tactics = ", ".join(inc.mitre_tactics) if inc.mitre_tactics else "N/A"
            techs = ", ".join(inc.mitre_techniques) if inc.mitre_techniques else "N/A"

            body = (
                f"[bold white]Title:[/bold white] {inc.title}\n"
                f"[bold white]Target Entity:[/bold white] {inc.entity.name} (PID: {inc.entity.pid or 'N/A'}, Path: {inc.entity.path or 'N/A'})\n"
                f"[bold white]Root Cause:[/bold white] {inc.explanation}\n"
                f"[bold cyan]MITRE Tactics:[/bold cyan] {tactics}\n"
                f"[bold cyan]MITRE Techniques:[/bold cyan] {techs}\n"
                f"[bold green]Suggested SOAR Remediation:[/bold green] {inc.remediation}\n"
                f"[dim]Evidence: {len(inc.evidence)} atomic signals correlated[/dim]"
            )
            console.print(Panel(body, title=f"[{sev_color}][{i}] {inc.severity.value.upper()} — {inc.incident_id}[/{sev_color}]", box=box.HEAVY))
    else:
        console.print("\n[bold green]✓ ZERO CORRELATED INCIDENTS. All endpoint activities adhere to benign baselines.[/bold green]")


def main():
    parser = argparse.ArgumentParser(description="Aegis-X Autonomous EDR & SOC Platform")
    subparsers = parser.add_subparsers(dest="command")

    # scan command
    scan_p = subparsers.add_parser("scan", help="Run endpoint scan")
    scan_p.add_argument("--mode", choices=["live", "simulation", "hybrid"], default="hybrid", help="Scan execution mode")
    scan_p.add_argument("--scenario", default="all_threats", help="Simulation scenario")

    # server command
    server_p = subparsers.add_parser("server", help="Launch SOC Web Operations Center")
    server_p.add_argument("--host", default="127.0.0.1", help="Bind host")
    server_p.add_argument("--port", type=int, default=8000, help="Bind port")

    args = parser.parse_args()

    if args.command == "server":
        console.print(BANNER)
        console.print(f"[bold cyan]🚀 Launching Aegis-X SOC Cyber Operations Center on http://{args.host}:{args.port}[/bold cyan]")
        uvicorn.run("aegis.server.app:app", host=args.host, port=args.port, reload=False, log_level="info")
    else:
        mode = getattr(args, "mode", "hybrid")
        scenario = getattr(args, "scenario", "all_threats")
        cli_scan(mode=mode, scenario=scenario)


if __name__ == "__main__":
    main()
