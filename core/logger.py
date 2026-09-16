from __future__ import annotations
import sys
from pathlib import Path

from loguru import logger
from rich.console import Console

console = Console()
_configured = False


def setup_logging(verbose: bool = False, log_file: str = "./loot/chainpwn.log") -> None:
    global _configured
    if _configured:
        return
    logger.remove()
    level = "DEBUG" if verbose else "INFO"
    logger.add(
        sys.stderr,
        level=level,
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan> - <level>{message}</level>",
        colorize=True,
    )
    try:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        logger.add(log_file, level="DEBUG", rotation="10 MB", retention=5)
    except Exception:
        pass
    _configured = True


log = logger
