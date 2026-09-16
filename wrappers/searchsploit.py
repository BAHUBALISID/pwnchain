from __future__ import annotations
import json

from wrappers.base import BaseTool


class SearchsploitTool(BaseTool):
    name = "searchsploit"

    async def search(self, term: str) -> list[dict]:
        args = ["--json", "-w", term]
        _, out, _ = await self.run_cmd(args, timeout=120)
        if not out.strip():
            return []
        try:
            data = json.loads(out)
        except Exception:
            return []

        results: list[dict] = []
        for entry in data.get("RESULTS_EXPLOIT", []) or []:
            results.append({
                "edb_id": entry.get("EDB-ID"),
                "title": entry.get("Title"),
                "type": entry.get("Type"),
                "platform": entry.get("Platform"),
                "path": entry.get("Path"),
                "date": entry.get("Date"),
            })
        for entry in data.get("RESULTS_SHELLCODE", []) or []:
            results.append({
                "edb_id": entry.get("EDB-ID"),
                "title": entry.get("Title"),
                "type": "shellcode",
                "platform": entry.get("Platform"),
                "path": entry.get("Path"),
            })
        return results

    async def search_cve(self, cve: str) -> list[dict]:
        return await self.search(cve)

    async def search_version(self, product: str, version: str) -> list[dict]:
        return await self.search(f"{product} {version}".strip())
