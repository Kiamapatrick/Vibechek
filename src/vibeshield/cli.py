import asyncio
import logging
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from vibeshield.config import settings
from vibeshield.reporting.json import JSONReporter
from vibeshield.reporting.plain import PlainReporter
from vibeshield.scanner.engine import ScannerEngine
from vibeshield.triage.pipeline import run_full_pipeline

app = typer.Typer(
    name="vibeshield",
    help="Security scanner for AI-assisted/vibe-coded web apps",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
console = Console()


def version_callback(value: bool) -> None:
    if value:
        console.print(f"VibeShield v{settings.VERSION}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool | None = typer.Option(
        None, "--version", "-v", callback=version_callback, is_eager=True,
        help="Show version and exit"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Enable verbose logging (DEBUG level)",
    ),
) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


@app.command()
def scan(
    url: str = typer.Argument(..., help="Target URL to scan (must include http:// or https://)"),
    confirm_ownership: bool = typer.Option(
        False, "--confirm-ownership", "-y",
        help="Confirm you own or have permission to scan this target (REQUIRED)",
    ),
    allow_write_tests: bool = typer.Option(
        False, "--allow-write-tests",
        help="Allow write-based tests (e.g. Supabase RLS insert probe) that may create test data on the target. Off by default — read-only checks are sufficient for most findings.",
    ),
    output: str = typer.Option(
        "plain", "--output", "-o",
        help="Output format: plain, json, or both",
    ),
    output_file: Path | None = typer.Option(  # noqa: B008
        None, "--output-file", "-f",
        help="Write report to file instead of stdout",
    ),
    timeout: float = typer.Option(
        settings.DEFAULT_TIMEOUT, "--timeout", "-t",
        help="Request timeout in seconds",
    ),
    max_pages: int = typer.Option(
        settings.DEFAULT_MAX_PAGES, "--max-pages",
        help="Maximum pages to crawl",
    ),
    max_depth: int = typer.Option(
        settings.DEFAULT_MAX_DEPTH, "--max-depth",
        help="Maximum crawl depth",
    ),
) -> None:
    """
    Scan a deployed web application for common vibe-coding security issues.

    [bold red]IMPORTANT:[/bold red] You must confirm ownership with --confirm-ownership/-y flag.
    Scanning targets you don't own is unethical and may be illegal.
    """
    if not confirm_ownership:
        console.print(Panel(
            "[bold red]Error:[/bold red] You must confirm ownership of the target.\n"
            "Add [bold]--confirm-ownership[/bold] or [bold]-y[/bold] flag to proceed.\n\n"
            "[yellow]Ethical Use Reminder:[/yellow] Only scan applications you own or have "
            "explicit written permission to test. Unauthorized scanning is unethical "
            "and may violate laws including the CFAA (US) and Computer Misuse Act (UK).",
            title="[red]Ownership Confirmation Required[/red]",
            border_style="red",
        ))
        raise typer.Exit(code=1)

    if allow_write_tests:
        console.print(Panel(
            "[bold yellow]Warning:[/bold yellow] This will attempt to insert test data into discovered database tables.\n"
            "Only use this against systems you own.",
            title="[yellow]Write Tests Enabled[/yellow]",
            border_style="yellow",
        ))

    if not url.startswith(("http://", "https://")):
        console.print("[red]Error:[/red] URL must start with http:// or https://")
        raise typer.Exit(code=1)

    if output not in ("plain", "json", "both"):
        console.print(f"[red]Error:[/red] Invalid output format: {output}. Use: plain, json, or both")
        raise typer.Exit(code=1)

    console.print(Panel(
        f"[bold]Target:[/bold] {url}\n"
        f"[bold]Max pages:[/bold] {max_pages} | [bold]Max depth:[/bold] {max_depth} | [bold]Timeout:[/bold] {timeout}s\n"
        f"[bold]Output:[/bold] {output}",
        title="[blue]VibeShield Scan Starting[/blue]",
        border_style="blue",
    ))

    engine = ScannerEngine(
        target_url=url,
        max_depth=max_depth,
        max_pages=max_pages,
        timeout=timeout,
        allow_write_tests=allow_write_tests,
    )

    try:
        plain_report, json_report = asyncio.run(engine.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(code=130)
    except Exception as e:  # noqa: BLE001 -- top-level CLI guard, must catch anything to fail gracefully
        console.print(f"[red]Scan failed:[/red] {e}")
        import traceback
        console.print(traceback.format_exc())
        raise typer.Exit(code=1)

    output_content = ""
    if output in ("plain", "both"):
        output_content += PlainReporter.generate(plain_report)
    if output in ("json", "both"):
        if output_content:
            output_content += "\n\n"
        output_content += JSONReporter.generate(json_report)

    if output_file:
        output_file.write_text(output_content, encoding="utf-8")
        console.print(f"\n[green]Report saved to:[/green] {output_file}")
    else:
        console.print("\n" + output_content)

    if plain_report.summary.critical > 0:
        raise typer.Exit(code=2)
    elif plain_report.summary.high > 0:
        raise typer.Exit(code=3)


@app.command()
def triage(
    report_path: Path = typer.Argument(..., help="Path to JSON scan report file", exists=True),  # noqa: B008
    output_file: Path | None = typer.Option(  # noqa: B008
        None, "--output-file", "-f",
        help="Write triage report to file instead of stdout",
    ),
) -> None:
    """
    Run LLM triage on a scan report and generate a prioritized triage report.
    
    Reads a JSON scan report (output from 'vibeshield scan --output json'),
    triages every finding via LLM (with baseline fallback), and produces
    a formatted triage report.
    """
    console.print(Panel(
        f"[bold]Report:[/bold] {report_path}",
        title="[blue]VibeShield Triage Starting[/blue]",
        border_style="blue",
    ))

    try:
        report_text = run_full_pipeline(report_path)
    except Exception as e:  # noqa: BLE001 -- top-level CLI guard
        console.print(f"[red]Triage failed:[/red] {e}")
        import traceback
        console.print(traceback.format_exc())
        raise typer.Exit(code=1)

    if output_file:
        output_file.write_text(report_text, encoding="utf-8")
        console.print(f"\n[green]Triage report saved to:[/green] {output_file}")
    else:
        console.print("\n" + report_text)


if __name__ == "__main__":
    app()