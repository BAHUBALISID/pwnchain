from __future__ import annotations
import re

from wrappers.base import BaseTool


class GobusterTool(BaseTool):
    name = "gobuster"

    async def dir_scan(self, url: str, wordlist: str, extensions: list[str] | None = None) -> list[dict]:
        args = ["dir", "-u", url, "-w", wordlist, "-q", "--no-error"]
        if extensions:
            args += ["-x", ",".join(e.lstrip(".") for e in extensions)]
        _, out, _ = await self.run_cmd(args, timeout=1800)
        return self._parse(out)

    def _parse(self, out: str) -> list[dict]:
        results: list[dict] = []
        pattern = re.compile(r"^(/\S+)\s+\(Status:\s+(\d+)\)")
        for line in out.splitlines():
            m = pattern.match(line.strip())
            if m:
                results.append({"path": m.group(1), "status": int(m.group(2))})
        return results
