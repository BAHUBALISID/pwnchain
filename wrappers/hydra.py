from __future__ import annotations
import re

from wrappers.base import BaseTool


class HydraTool(BaseTool):
    name = "hydra"

    async def brute(
        self,
        service: str,
        host: str,
        userlist: str,
        passlist: str,
        port: int | None = None,
        extra: list[str] | None = None,
    ) -> list[dict]:
        args = list(self.cfg.get("hydra", "default_flags", default=["-f", "-V", "-t", "4"]) or [])
        if port:
            args += ["-s", str(port)]
        args += ["-L", userlist, "-P", passlist]
        if extra:
            args += extra
        args += [host, service]
        _, out, _ = await self.run_cmd(args, timeout=3600)
        return self._parse(out)

    async def brute_single_user(
        self,
        service: str,
        host: str,
        user: str,
        passlist: str,
        port: int | None = None,
    ) -> list[dict]:
        args = ["-f", "-V", "-t", "4"]
        if port:
            args += ["-s", str(port)]
        args += ["-l", user, "-P", passlist, host, service]
        _, out, _ = await self.run_cmd(args, timeout=3600)
        return self._parse(out)

    def _parse(self, out: str) -> list[dict]:
        results: list[dict] = []
        pat = re.compile(
            r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)"
        )
        for line in out.splitlines():
            m = pat.search(line)
            if m:
                results.append({
                    "port": int(m.group(1)),
                    "service": m.group(2),
                    "host": m.group(3),
                    "username": m.group(4),
                    "password": m.group(5),
                })
        return results
