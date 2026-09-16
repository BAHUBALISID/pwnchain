from __future__ import annotations
from core.state import Session


WINDOWS_CMDS = [
    "whoami /all",
    "systeminfo",
    "ipconfig /all",
    "net user",
    "net localgroup administrators",
    "wmic service get name,displayname,pathname,startmode",
    "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "dir C:\\Users",
]


class WindowsEnum:
    def __init__(self, handler):
        self.handler = handler

    async def run(self, session: Session) -> dict:
        results: dict = {}
        for c in WINDOWS_CMDS:
            results[c] = await self.handler.send(session, c)
        return results
