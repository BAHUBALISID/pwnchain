from __future__ import annotations
import asyncio

from core.logger import log
from core.state import Finding, Severity
from matcher.tech_matcher import TechMatcher


class CVELookup:
    def __init__(self, cfg, searchsploit=None, msf=None):
        self.cfg = cfg
        self.searchsploit = searchsploit
        self.msf = msf
        self.tech = TechMatcher()

    async def lookup_for_services(self, services: list, target) -> list[Finding]:
        findings: list[Finding] = []
        tasks = [self._lookup_service(svc, target) for svc in services]
        for coro in asyncio.as_completed(tasks):
            try:
                findings.extend(await coro)
            except Exception as e:
                log.debug(f"lookup task failed: {e}")
        return findings

    async def _lookup_service(self, svc, target) -> list[Finding]:
        results: list[Finding] = []
        keywords = self.tech.keywords(svc.product or svc.name, svc.version)
        if not keywords:
            return results

        seen_edb: set[str] = set()
        if self.searchsploit:
            for kw in keywords[:6]:
                try:
                    edb = await self.searchsploit.search(kw)
                except Exception:
                    edb = []
                for e in edb:
                    eid = str(e.get("edb_id") or "")
                    if not eid or eid in seen_edb:
                        continue
                    seen_edb.add(eid)
                    results.append(Finding(
                        title=e.get("title") or f"EDB-{eid}",
                        severity=Severity.HIGH,
                        source="searchsploit",
                        target=f"{target.host}:{svc.port}",
                        edb_id=eid,
                        description=f"{e.get('type')} | {e.get('platform')}",
                        evidence=e.get("path", ""),
                        metadata={"keyword": kw, "service": svc.key},
                    ))

        if self.msf:
            seen_modules: set[str] = set()
            for kw in keywords[:4]:
                try:
                    mods = self.msf.search(kw)
                except Exception:
                    mods = []
                for m in mods:
                    if isinstance(m, dict):
                        name = m.get("fullname", "") or m.get("name", "")
                        desc = m.get("description", "")
                        disp = m.get("name", name)
                    else:
                        name = str(m)
                        desc = ""
                        disp = name
                    if not name.startswith(("exploit/", "auxiliary/")):
                        continue
                    if name in seen_modules:
                        continue
                    seen_modules.add(name)
                    results.append(Finding(
                        title=disp,
                        severity=Severity.HIGH,
                        source="metasploit",
                        target=f"{target.host}:{svc.port}",
                        msf_module=name,
                        description=desc,
                        metadata={"keyword": kw, "service": svc.key},
                    ))
        return results
