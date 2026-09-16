from __future__ import annotations
import asyncio
import shutil
from pathlib import Path

from core.logger import log
from core.state import Finding, Target


class EDBExecutor:
    def __init__(self, cfg):
        self.cfg = cfg

    async def run(self, finding: Finding, target: Target) -> bool:
        if not finding.evidence:
            return False
        path = Path(finding.evidence)
        if not path.exists():
            log.debug(f"EDB path missing: {path}")
            return False

        suffix = path.suffix.lower()
        if suffix == ".py":
            cmd = ["python3", str(path)]
        elif suffix == ".rb":
            cmd = ["ruby", str(path)]
        elif suffix == ".sh":
            cmd = ["bash", str(path)]
        elif suffix == ".c":
            return await self._compile_and_run(path)
        else:
            log.debug(f"Unsupported EDB type: {suffix}")
            return False

        log.info(f"Running EDB: {' '.join(cmd)}")
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
            log.debug(out.decode(errors="replace")[:500])
            return proc.returncode == 0
        except Exception as e:
            log.warning(f"EDB run failed: {e}")
            return False

    async def _compile_and_run(self, src: Path) -> bool:
        out = src.with_suffix("")
        cc = shutil.which("gcc") or shutil.which("cc")
        if not cc:
            return False
        try:
            proc = await asyncio.create_subprocess_exec(
                cc, str(src), "-o", str(out),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            if proc.returncode != 0:
                return False

            p = await asyncio.create_subprocess_exec(
                str(out),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(p.communicate(), timeout=120)
            return True
        except Exception:
            return False
