from __future__ import annotations
import json

from wrappers.base import BaseTool


class WPScanTool(BaseTool):
    name = "wpscan"

    async def scan(self, url: str, api_token: str | None = None) -> dict:
        args = list(self.cfg.get("wpscan", "default_flags", default=[]) or []) + ["--url", url]
        if api_token:
            args += ["--api-token", api_token]
        _, out, err = await self.run_cmd(args, timeout=1800)
        try:
            return json.loads(out)
        except Exception:
            return {"raw": out, "stderr": err}
