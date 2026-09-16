from __future__ import annotations
import asyncio
from typing import Optional


async def run(
    cmd: list[str],
    timeout: Optional[int] = None,
    input_data: Optional[bytes] = None,
    cwd: Optional[str] = None,
) -> tuple[int, str, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if input_data is not None else None,
            cwd=cwd,
        )
    except FileNotFoundError:
        return 127, "", f"{cmd[0]} not found"

    try:
        if timeout is not None:
            out, err = await asyncio.wait_for(proc.communicate(input_data), timeout=timeout)
        else:
            out, err = await proc.communicate(input_data)
    except asyncio.TimeoutError:
        proc.kill()
        return -1, "", "timeout"
    return proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")
