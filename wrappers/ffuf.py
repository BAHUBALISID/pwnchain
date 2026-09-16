from __future__ import annotations
import asyncio
import json
import tempfile
from pathlib import Path
from typing import Optional

from core.logger import log
from wrappers.base import BaseTool


class FfufTool(BaseTool):
    name = "ffuf"

    async def _run_list(
        self,
        url_template: str,
        wordlist: str,
        extra: list[str],
        threads: int,
        extensions: list[str],
        task_name: str,
    ) -> list[dict]:
        if not Path(wordlist).exists():
            log.debug(f"wordlist missing: {wordlist}")
            return []

        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as tf:
            out_path = tf.name

        args = [
            "-u", url_template,
            "-w", wordlist,
            "-of", "json",
            "-o", out_path,
            "-t", str(threads),
            "-s",
        ] + extra
        if extensions:
            args += ["-e", ",".join(extensions)]

        await self.run_cmd(args, timeout=3600)

        hits: list[dict] = []
        try:
            raw = Path(out_path).read_text()
            data = json.loads(raw) if raw.strip() else {}
        except Exception:
            data = {}
        finally:
            Path(out_path).unlink(missing_ok=True)

        for r in data.get("results", []) or []:
            hits.append({
                "url": r.get("url"),
                "status": r.get("status"),
                "length": r.get("length"),
                "words": r.get("words"),
                "task": task_name,
                "wordlist": Path(wordlist).name,
            })
        return hits

    async def fuzz_dir(self, url: str, preset: str) -> list[dict]:
        strategy, lists = self.cfg.resolve_lists("dir", preset)
        stage = self.cfg.stage("dir")
        extensions = stage.get("extensions", []) or []
        base = url.rstrip("/") + "/FUZZ"
        return await self._run_strategy(
            strategy, lists, base, extensions, "ffuf_dir",
            autocalibrate=True, extra=None,
        )

    async def fuzz_vhost(self, host: str, url: str, preset: str) -> list[dict]:
        strategy, lists = self.cfg.resolve_lists("vhost", preset)
        base = url
        extra = ["-H", f"Host: FUZZ.{host}"]
        return await self._run_strategy(
            strategy, lists, base, [], "ffuf_vhost",
            autocalibrate=False, extra=extra,
        )

    async def fuzz_param(self, url: str, preset: str) -> list[dict]:
        strategy, lists = self.cfg.resolve_lists("param", preset)
        base = url + "?FUZZ=test"
        return await self._run_strategy(
            strategy, lists, base, [], "ffuf_param",
            autocalibrate=True, extra=None,
        )

    async def _run_strategy(
        self,
        strategy: str,
        lists: list[dict],
        base: str,
        extensions: list[str],
        task: str,
        autocalibrate: bool = False,
        extra: Optional[list[str]] = None,
    ) -> list[dict]:
        extra = list(extra or [])
        if autocalibrate:
            extra += ["-ac"]
        results: list[dict] = []

        if not lists:
            return results

        if strategy == "parallel":
            coros = [
                self._run_list(base, e["path"], extra, e.get("threads", 40),
                               extensions, f"{task}:{e['name']}")
                for e in lists
            ]
            for chunk in await asyncio.gather(*coros, return_exceptions=True):
                if isinstance(chunk, list):
                    results.extend(chunk)
            return results

        if strategy == "merge":
            merged = self._merge_lists(lists)
            if merged:
                try:
                    results.extend(
                        await self._run_list(base, merged, extra, 40, extensions, f"{task}:merged")
                    )
                finally:
                    Path(merged).unlink(missing_ok=True)
            return results

        if strategy == "sequential":
            for e in lists:
                results.extend(
                    await self._run_list(base, e["path"], extra, e.get("threads", 40),
                                         extensions, f"{task}:{e['name']}")
                )
            return results

        for e in lists:
            hits = await self._run_list(base, e["path"], extra, e.get("threads", 40),
                                        extensions, f"{task}:{e['name']}")
            if hits:
                return hits
        return results

    def _merge_lists(self, lists: list[dict]) -> Optional[str]:
        lines: set[str] = set()
        for e in lists:
            p = Path(e["path"])
            if not p.exists():
                continue
            for ln in p.read_text(errors="ignore").splitlines():
                ln = ln.strip()
                if ln:
                    lines.add(ln)
        if not lines:
            return None
        tmp = tempfile.NamedTemporaryFile("w+", delete=False, suffix=".txt")
        tmp.write("\n".join(sorted(lines)))
        tmp.close()
        return tmp.name
