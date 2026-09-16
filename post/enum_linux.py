from __future__ import annotations
from core.state import Session


LINUX_CMDS = [
    "id",
    "uname -a",
    "cat /etc/os-release",
    "hostname",
    "whoami",
    "sudo -l",
    "cat /etc/passwd",
    "ls -la /home/*",
    "find / -perm -4000 -type f 2>/dev/null",
    "getcap -r / 2>/dev/null",
    "crontab -l",
    "cat /etc/crontab",
    "ls -la /etc/cron.*",
    "ip a",
    "ss -tlnp",
    "env",
]


class LinuxEnum:
    def __init__(self, handler):
        self.handler = handler

    async def run(self, session: Session) -> dict:
        results: dict = {}
        for c in LINUX_CMDS:
            results[c] = await self.handler.send(session, c)
        return results
