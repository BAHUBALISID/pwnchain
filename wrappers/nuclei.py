from __future__ import annotations
import json
import tempfile
from pathlib import Path
from typing import Optional

from core.state import Finding, Severity
from wrappers.base import BaseTool


class NucleiTool(BaseTool):
    name = "nuclei"

    async def scan(
        self,
        url: str,
        tags: Optional[list[str]] = None,
        severity: Optional[list[str]] = None,
    ) -> list[Finding]:
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".jsonl") as tf:
            out_path = tf.name

        args = ["-u", url, "-jsonl", "-silent", "-o", out_path]
        if tags:
            args += ["-tags", ",".join(tags)]
        sev = severity if severity is not None else self.cfg.get("nuclei", "severity", default=None)
        if sev:
            args += ["-severity", ",".join(sev)]

        await self.run_cmd(args, timeout=1800)

        findings: list[Finding] = []
        try:
            raw = Path(out_path).read_text()
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except Exception:
                    continue
                findings.append(self._to_finding(data, url))
        finally:
            Path(out_path).unlink(missing_ok=True)
        return findings

    def _to_finding(self, data: dict, url: str) -> Finding:
        info = data.get("info", {}) or {}
        sev = (info.get("severity") or "info").lower()
        sev_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
            "unknown": Severity.INFO,
        }
        return Finding(
            title=info.get("name", data.get("template-id", "nuclei")),
            severity=sev_map.get(sev, Severity.INFO),
            source="nuclei",
            target=url,
            description=info.get("description", ""),
            evidence=data.get("matched-at", ""),
            nuclei_template=data.get("template-id"),
            cve=(info.get("classification") or {}).get("cve-id"),
            metadata={"tags": info.get("tags", []), "raw": data},
        )
