from __future__ import annotations
import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from core.config import load_config
from core.logger import setup_logging
from core.orchestrator import Orchestrator
from core.state import Target
from utils.validators import validate_target

app = typer.Typer(add_completion=False, help="ChainPwn")
console = Console()


@app.command()
def run(
    target: str = typer.Argument(..., help="IP, hostname or URL"),
    preset: str = typer.Option("normal", "--preset", "-p"),
    profile: str = typer.Option("auto", "--profile"),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
    no_msf: bool = typer.Option(False, "--no-msf"),
    output: Path = typer.Option(Path("./loot"), "--output", "-o"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    setup_logging(verbose=verbose)
    validate_target(target)
    cfg = load_config(config)
    tgt = Target.from_string(target)
    orch = Orchestrator(cfg=cfg, preset=preset, profile=profile,
                        use_msf=not no_msf, loot_dir=output)
    try:
        asyncio.run(orch.run(tgt))
    except KeyboardInterrupt:
        console.print("[yellow]Interrupted[/yellow]")
        orch.save_state()


@app.command()
def resume(state_file: Path = typer.Argument(...)) -> None:
    setup_logging()
    asyncio.run(Orchestrator.resume(state_file))


@app.command()
def report(loot: Path = typer.Argument(Path("./loot"))) -> None:
    from reports.writer import ReportWriter
    ReportWriter(loot).render_all()
    console.print(f"[green]Reports written to {loot}[/green]")


if __name__ == "__main__":
    app()
