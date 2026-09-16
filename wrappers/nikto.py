from __future__ import annotations

from wrappers.base import BaseTool


class NiktoTool(BaseTool):
    name = "nikto"

    async def scan(self, url: str) -> dict:
        args = list(self.cfg.get("nikto", "default_flags", default=[]) or []) + ["-h", url]
        code, out, err = await self.run_cmd(args, timeout=1800)
        return {"raw": out, "stderr": err, "rc": code}
