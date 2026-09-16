from __future__ import annotations
from typing import Optional

import aiohttp


async def get(
    url: str,
    timeout: int = 15,
    headers: Optional[dict] = None,
    allow_redirects: bool = True,
) -> tuple[int, str, dict]:
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(
                url, timeout=timeout, headers=headers,
                allow_redirects=allow_redirects, ssl=False,
            ) as r:
                text = await r.text(errors="replace")
                return r.status, text, dict(r.headers)
    except Exception as e:
        return 0, "", {"error": str(e)}


async def head(url: str, timeout: int = 10) -> int:
    try:
        async with aiohttp.ClientSession() as s:
            async with s.head(
                url, timeout=timeout, ssl=False, allow_redirects=True,
            ) as r:
                return r.status
    except Exception:
        return 0
