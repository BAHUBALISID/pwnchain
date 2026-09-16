from __future__ import annotations
import json

from wrappers.base import BaseTool


class WhatWebTool(BaseTool):
    name = "whatweb"

    async def fingerprint(self, url: str) -> dict:
        args = list(self.cfg.get("whatweb", "default_flags", default=[]) or []) + [url]
        _, out, _ = await self.run_cmd(args, timeout=180)

        plugins: list[str] = []
        for ln in out.splitlines():
            ln = ln.strip()
            if not ln.startswith("{"):
                continue
            try:
                data = json.loads(ln)
            except Exception:
                continue
            for plug in (data.get("plugins") or {}).keys():
                plugins.append(plug)

        product, version = "", ""
        for p in plugins:
            if "/" in p:
                name, ver = p.split("/", 1)
                product, version = name, ver
                break

        return {"plugins": plugins, "product": product, "version": version, "raw": out}
