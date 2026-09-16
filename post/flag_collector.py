from __future__ import annotations
import asyncio
import re

from core.state import Flag, Session


FLAG_PATHS = [
    "/root/root.txt",
    "/root/flag.txt",
    "/home/*/user.txt",
    "/home/*/flag.txt",
    "/flag.txt",
    "/var/www/flag.txt",
]

FLAG_REGEX = re.compile(
    r"(?:[0-9a-f]{32}|flag\{[^}]+\}|HTB\{[^}]+\}|CTF\{[^}]+\})",
    re.I,
)


class FlagCollector:
    def __init__(self, cfg):
        self.cfg = cfg

    async def collect(self, session: Session, state) -> list[Flag]:
        from post.shell_handler import ShellHandler
        handler = getattr(self, "_handler", None)
        if handler is None:
            return []
        flags: list[Flag] = []
        for path in FLAG_PATHS:
            out = await handler.send(session, f"cat {path} 2>/dev/null", read_timeout=8)
            if not out:
                continue
            for m in FLAG_REGEX.findall(out):
                flags.append(Flag(name=path.split("/")[-1], value=m, path=path))

        if not flags:
            out = await handler.send(
                session,
                "find / -maxdepth 4 \\( -iname '*flag*' -o -iname 'user.txt' -o -iname 'root.txt' \\) 2>/dev/null | head -20",
                read_timeout=20,
            )
            for m in FLAG_REGEX.findall(out or ""):
                flags.append(Flag(name="flag", value=m, path="search"))
        return flags

    def attach(self, handler) -> None:
        self._handler = handler
