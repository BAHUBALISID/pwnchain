from __future__ import annotations
import asyncio
from datetime import datetime, timezone
from pathlib import Path

from core.config import Config, load_config
from core.database import Database
from core.logger import log
from core.state import Service, Target, RunState
from matcher.cve_lookup import CVELookup
from matcher.ranker import Ranker
from matcher.applicability import Applicability
from wrappers.nmap import NmapTool
from wrappers.ffuf import FfufTool
from wrappers.whatweb import WhatWebTool
from wrappers.searchsploit import SearchsploitTool
from wrappers.msf import MetasploitTool
from executors.msf_executor import MSFExecutor
from executors.nuclei_executor import NucleiExecutor
from post.shell_handler import ShellHandler
from post.flag_collector import FlagCollector
from reports.writer import ReportWriter

WEB_PORTS = (80, 443, 8000, 8080, 8443, 8888)


class Orchestrator:
    def __init__(self, cfg: Config, preset: str = "normal", profile: str = "auto",
                 use_msf: bool = True, loot_dir: Path = Path("./loot")):
        self.cfg = cfg
        self.preset = preset
        self.profile = profile
        self.use_msf = use_msf
        self.loot_dir = Path(loot_dir)
        self.loot_dir.mkdir(parents=True, exist_ok=True)
        self.state = RunState()
        self.db = Database(self.loot_dir / "chainpwn.db")

    async def run(self, target: Target) -> RunState:
        self.state.target = target
        log.info(f"ChainPwn → {target.host} (preset={self.preset}, profile={self.profile})")

        try:
            await self._recon(target)
            await self._fingerprint(target)
            findings = await self._match(target)
            ranked = Ranker().rank(findings)
            await self._execute(target, ranked)
            await self._post(target)
        except Exception as e:
            log.exception(f"orchestrator error: {e}")
            self.state.errors.append(str(e))
        finally:
            self._finalize()
        return self.state

    async def _recon(self, target: Target) -> None:
        try:
            nmap = NmapTool(self.cfg)
            services = await nmap.scan(target)
        except Exception as e:
            log.warning(f"nmap failed: {e}")
            services = []

        for s in services:
            self.state.add_service(s)
        self.state.tool_outputs["nmap"] = [s.to_dict() for s in services]

        web = [s for s in services if s.port in WEB_PORTS]
        if not web and not target.is_ip:
            web = [Service(
                port=target.port or (443 if target.scheme == "https" else 80),
                name="https" if target.scheme == "https" else "http",
                url=target.base_url,
            )]
            for s in web:
                self.state.add_service(s)

        for svc in web:
            url = svc.url or self._url_for(target, svc)
            svc.url = url
            if self.cfg.stage("dir").get("enabled", True):
                try:
                    ff = FfufTool(self.cfg)
                    hits = await ff.fuzz_dir(url, self.preset)
                    self.state.tool_outputs.setdefault("ffuf_dir", []).extend(hits)
                except Exception as e:
                    log.warning(f"ffuf dir failed on {url}: {e}")
            if self.cfg.stage("vhost").get("enabled", True) and target.is_ip:
                try:
                    ff = FfufTool(self.cfg)
                    vhosts = await ff.fuzz_vhost(target.host, url, self.preset)
                    self.state.tool_outputs.setdefault("vhost", []).extend(vhosts)
                except Exception as e:
                    log.warning(f"ffuf vhost failed: {e}")

    def _url_for(self, target: Target, svc: Service) -> str:
        scheme = "https" if svc.port in (443, 8443) else "http"
        return f"{scheme}://{target.host}:{svc.port}"

    async def _fingerprint(self, target: Target) -> None:
        web = [s for s in self.state.services if s.port in WEB_PORTS or s.url]
        if not web:
            return
        try:
            ww = WhatWebTool(self.cfg)
        except Exception as e:
            log.debug(f"whatweb unavailable: {e}")
            ww = None

        for svc in web:
            url = svc.url or self._url_for(target, svc)
            if ww:
                try:
                    info = await ww.fingerprint(url)
                    svc.product = info.get("product") or svc.product
                    svc.version = info.get("version") or svc.version
                    svc.extra["whatweb"] = info
                except Exception as e:
                    log.debug(f"whatweb on {url}: {e}")

        try:
            ne = NucleiExecutor(self.cfg)
            results = await ne.run(target, self.state)
            log.info(f"nuclei: {len(results)} finding(s)")
        except Exception as e:
            log.warning(f"nuclei failed: {e}")

    async def _match(self, target: Target) -> list:
        try:
            searcher = SearchsploitTool(self.cfg)
        except Exception:
            searcher = None

        msf = None
        if self.use_msf:
            msf = MetasploitTool(self.cfg)
            ok = await msf.connect()
            if not ok:
                log.warning("MSF RPC not reachable — continuing without MSF")
                msf = None

        lookup = CVELookup(self.cfg, searcher, msf)
        findings = await lookup.lookup_for_services(self.state.services, target)

        app = Applicability(self.cfg)
        findings = [f for f in findings if app.check(f, self.state)]
        for f in findings:
            self.state.add_finding(f)
        log.info(f"Matcher produced {len(findings)} candidate(s)")
        return findings

    async def _execute(self, target: Target, ranked: list) -> None:
        if not ranked:
            log.info("No exploits to run")
            return

        shell = ShellHandler(self.cfg)
        await shell.start_listener()

        for finding in ranked[:5]:
            log.info(f"Attempting: {finding.title} (score={finding.score:.2f})")
            try:
                if finding.msf_module and self.use_msf:
                    executor = MSFExecutor(self.cfg)
                    ok = await executor.run(finding, target, self.state)
                    if ok:
                        wait = self.cfg.get("general", "shell_wait_seconds", default=45)
                        sess = await shell.wait_for_session(wait)
                        if sess:
                            self.state.add_session(sess)
                            shell.close_async()
                            return
                elif finding.nuclei_template:
                    executor = NucleiExecutor(self.cfg)
                    await executor.run_single(finding.nuclei_template, target)
            except Exception as e:
                log.warning(f"executor failed for {finding.title}: {e}")
                self.state.errors.append(f"{finding.title}: {e}")

        shell.close_async()

    async def _post(self, target: Target) -> None:
        if not self.state.sessions:
            return
        try:
            collector = FlagCollector(self.cfg)
            flags = await collector.collect(self.state.sessions[-1], self.state)
            for f in flags:
                self.state.add_flag(f)
            log.info(f"Collected {len(flags)} flag(s)")
        except Exception as e:
            log.warning(f"flag collection failed: {e}")

    def _finalize(self) -> None:
        self.state.finished = datetime.now(timezone.utc).isoformat()
        self.save_state()
        try:
            ReportWriter(self.loot_dir).render_all(self.state)
        except Exception as e:
            log.warning(f"report render failed: {e}")
        log.info(f"Done — state saved as {self.state.run_id}")

    def save_state(self) -> None:
        path = self.loot_dir / f"state_{self.state.run_id}.json"
        path.write_text(self.state.to_json())
        try:
            self.db.save_state(self.state)
        except Exception as e:
            log.warning(f"db save failed: {e}")

    @classmethod
    async def resume(cls, state_file: Path):
        raw = Path(state_file).read_text()
        st = RunState.from_json(raw)
        cfg = load_config()
        orch = cls(cfg=cfg, loot_dir=Path(state_file).parent)
        orch.state = st
        log.info(f"Resumed run {st.run_id}")
        if st.target:
            await orch._post(st.target)
        orch._finalize()
        return st
