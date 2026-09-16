from __future__ import annotations
from core.logger import log
from core.state import Target
from wrappers.nuclei import NucleiTool


class NucleiExecutor:
    def __init__(self, cfg):
        self.cfg = cfg

    async def run(self, target: Target, state) -> list:
        nuclei = NucleiTool(self.cfg)
        try:
            findings = await nuclei.scan(target.base_url)
        except Exception as e:
            log.warning(f"nuclei scan failed: {e}")
            return []
        for f in findings:
            state.add_finding(f)
        return findings

    async def run_single(self, template: str, target: Target) -> bool:
        nuclei = NucleiTool(self.cfg)
        try:
            results = await nuclei.scan(target.base_url, tags=[template])
            return bool(results)
        except Exception:
            return False
