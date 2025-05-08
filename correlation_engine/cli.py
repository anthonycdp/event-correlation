"""
Command Line Interface for the Security Event Correlation Engine.
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

from correlation_engine.engine import CorrelationEngine
from correlation_engine.models.event import SecurityEvent, EventSource, EventType, EventSeverity
from correlation_engine.rules.registry import RuleRegistry
from correlation_engine.utils.parsers import EventParser

console = Console()


def create_sample_events(count: int = 10) -> list[SecurityEvent]:
    """Generate sample events for testing."""
    from correlation_engine.utils.sample_data import generate_sample_events
    return generate_sample_events(count)


def process_events_file(filepath: str, engine: CorrelationEngine) -> list[dict]:
    """Process events from a JSON file."""
    with open(filepath) as f:
        data = json.load(f)

    if isinstance(data, list):
        events_data = data
    else:
        events_data = [data]

    parser = EventParser()
    alerts = []

    for event_data in events_data:
        event = parser.parse(event_data)
        if event:
            new_alerts = engine.process_event(event)
            alerts.extend([a.to_dict() for a in new_alerts])

    return alerts


def display_alerts(alerts: list, limit: int = 20) -> None:
    """Display alerts in a formatted table."""
    if not alerts:
        console.print("[yellow]No alerts to display[/yellow]")
        return

    table = Table(title="Security Alerts")
    table.add_column("ID", style="dim", width=8)
    table.add_column("Priority", style="bold")
    table.add_column("Title", width=40)
    table.add_column("Category", width=15)
    table.add_column("Events", justify="right", width=6)
    table.add_column("Source IPs", width=20)

    for alert in alerts[:limit]:
        priority = alert.priority if hasattr(alert, 'priority') else alert.get('priority', 'unknown')
        priority_colors = {
            'p1_critical': 'red',
            'p2_high': 'orange3',
            'p3_medium': 'yellow',
            'p4_low': 'blue',
            'p5_informational': 'dim',
        }
        color = priority_colors.get(priority, 'white')

        src_ips = alert.src_ips if hasattr(alert, 'src_ips') else alert.get('src_ips', [])

        table.add_row(
            alert.alert_id[:8] if hasattr(alert, 'alert_id') else alert.get('alert_id', '')[:8],
            f"[{color}]{priority}[/{color}]",
            alert.title if hasattr(alert, 'title') else alert.get('title', ''),
            (alert.category.value if hasattr(alert, 'category') else alert.get('category', ''))[:15],
            str(alert.event_count if hasattr(alert, 'event_count') else alert.get('event_count', 0)),
            ', '.join(src_ips[:2])[:20],
        )

    console.print(table)


def display_stats(engine: CorrelationEngine) -> None:
    """Display engine statistics."""
    stats = engine.get_stats()

    panel = Panel(
        f"""
[bold]Events Processed:[/bold] {stats['events_processed']}
[bold]Events Matched:[/bold] {stats['events_matched']}
[bold]Alerts Generated:[/bold] {stats['alerts_generated']}
[bold]False Positives Filtered:[/bold] {stats['false_positives_filtered']}
[bold]Buffer Size:[/bold] {stats['buffer_size']}
[bold]Active Alerts:[/bold] {stats['active_alerts']}
[bold]Enabled Rules:[/bold] {stats['enabled_rules']}
[bold]Uptime:[/bold] {stats['uptime_seconds']:.1f}s
        """.strip(),
        title="Engine Statistics",
        border_style="blue",
    )
    console.print(panel)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Security Event Correlation Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process a file of events
  sec-correlate process events.json --rules ./rules/

  # Generate sample events and process them
  sec-correlate demo --count 100

  # Run interactive mode
  sec-correlate interactive --rules ./rules/
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Process command
    process_parser = subparsers.add_parser("process", help="Process events from a file")
    process_parser.add_argument("file", help="JSON file containing events")
    process_parser.add_argument("--rules", "-r", help="Directory containing rule files")
    process_parser.add_argument("--output", "-o", help="Output file for alerts")
    process_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    # Demo command
    demo_parser = subparsers.add_parser("demo", help="Run a demo with sample events")
    demo_parser.add_argument("--count", "-c", type=int, default=50, help="Number of sample events")
    demo_parser.add_argument("--rules", "-r", help="Directory containing rule files")

    # Interactive command
    interactive_parser = subparsers.add_parser("interactive", help="Run in interactive mode")
    interactive_parser.add_argument("--rules", "-r", help="Directory containing rule files")

    # Stats command
    stats_parser = subparsers.add_parser("stats", help="Show engine statistics")
    stats_parser.add_argument("--rules", "-r", help="Directory containing rule files")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    # Initialize engine
    registry = RuleRegistry()
    if hasattr(args, 'rules') and args.rules:
        loaded = registry.load_from_directory(args.rules)
        console.print(f"[green]Loaded {loaded} rules from {args.rules}[/green]")

    # Load default rules
    from correlation_engine.utils.sample_data import get_default_rules
    for rule in get_default_rules():
        registry.register(rule)
    console.print(f"[green]Loaded {len(registry)} default rules[/green]")

    engine = CorrelationEngine(rule_registry=registry)

    if args.command == "process":
        console.print(f"[blue]Processing events from {args.file}...[/blue]")
        alerts = process_events_file(args.file, engine)
        display_alerts([a for a in alerts if not a.get('is_false_positive')])
        display_stats(engine)

        if args.output:
            with open(args.output, 'w') as f:
                json.dump(alerts, f, indent=2, default=str)
            console.print(f"[green]Alerts saved to {args.output}[/green]")

    elif args.command == "demo":
        console.print(f"[blue]Generating {args.count} sample events...[/blue]")
        events = create_sample_events(args.count)
        console.print(f"[green]Generated {len(events)} events[/green]")

        alerts = engine.process_events(events)
        console.print(f"[green]Generated {len(alerts)} alerts[/green]")

        display_alerts(alerts)
        display_stats(engine)

    elif args.command == "interactive":
        console.print(Panel.fit(
            "[bold blue]Security Event Correlation Engine[/bold blue]\n"
            "Type 'help' for available commands",
            border_style="blue",
        ))

        while True:
            try:
                cmd = console.input("[bold green]> [/bold green]").strip()

                if cmd in ('exit', 'quit', 'q'):
                    console.print("[yellow]Goodbye![/yellow]")
                    break
                elif cmd == 'help':
                    console.print("""
Available commands:
  help          - Show this help message
  stats         - Show engine statistics
  alerts        - Show current alerts
  demo [n]      - Generate and process n sample events (default: 10)
  whitelist ip  - Add IP to whitelist
  cleanup       - Run cleanup
  exit          - Exit interactive mode
                    """)
                elif cmd == 'stats':
                    display_stats(engine)
                elif cmd == 'alerts':
                    alerts = engine.get_alerts()
                    display_alerts(alerts)
                elif cmd.startswith('demo'):
                    parts = cmd.split()
                    count = int(parts[1]) if len(parts) > 1 else 10
                    events = create_sample_events(count)
                    alerts = engine.process_events(events)
                    display_alerts(alerts)
                    display_stats(engine)
                elif cmd.startswith('whitelist ip'):
                    parts = cmd.split()
                    if len(parts) >= 3:
                        ip = parts[2]
                        name = parts[3] if len(parts) > 3 else f"whitelist_{ip}"
                        engine.add_whitelist_ip(ip, name)
                        console.print(f"[green]Added {ip} to whitelist[/green]")
                elif cmd == 'cleanup':
                    result = engine.cleanup()
                    console.print(f"[green]Cleanup complete: {result}[/green]")
                else:
                    console.print(f"[red]Unknown command: {cmd}[/red]")

            except KeyboardInterrupt:
                console.print("\n[yellow]Use 'exit' to quit[/yellow]")
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")

    elif args.command == "stats":
        display_stats(engine)


if __name__ == "__main__":
    main()
