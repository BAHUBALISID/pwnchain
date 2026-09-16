from __future__ import annotations
import asyncio
import shutil
from typing import Optional

from core.config import Config
from core.logger import log


class BaseTool:
    name: str = "tool"

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.binary = self._resolve_binary()

    def _resolve_binary(self) -> str:
        configured = self.cfg.get(self.name, "binary", default=self.name) or self.name
        return shutil.which(configured) or configured

    async def run_cmd(
        self,
        args: list[str],
        timeout: Optional[int] = None,
        input_data: Optional[bytes] = None,
    ) -> tuple[int, str, str]:
        log.debug(f"exec: {self.binary} {' '.join(args)}")
        try:
            proc = await asyncio.create_subprocess_exec(
                self.binary, *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if input_data is not None else None,
            )
        except FileNotFoundError:
            return 127, "", f"{self.binary} not found"

        try:
            if timeout is not None:
                out, err = await asyncio.wait_for(proc.communicate(input_data), timeout=timeout)
            else:
                out, err = await proc.communicate(input_data)
        except asyncio.TimeoutError:
            proc.kill()
            return -1, "", "timeout"

        return proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")
