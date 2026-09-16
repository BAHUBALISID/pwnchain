from __future__ import annotations
import time

from core.logger import log
from core.exceptions import ToolNotFoundError


class MetasploitTool:
    name = "msf"

    def __init__(self, cfg):
        self.cfg = cfg
        self.client = None

    async def connect(self) -> bool:
        try:
            from pymetasploit3.msfrpc import MsfRpcClient
        except ImportError as e:
            raise ToolNotFoundError(f"pymetasploit3 missing: {e}")

        host = self.cfg.get("msf", "host", default="127.0.0.1")
        port = self.cfg.get("msf", "port", default=55553)
        user = self.cfg.get("msf", "user", default="msf")
        password = self.cfg.get("msf", "password", default="msf")
        ssl = self.cfg.get("msf", "ssl", default=True)

        for attempt in range(3):
            try:
                self.client = MsfRpcClient(
                    password, username=user, server=host, port=port, ssl=ssl,
                )
                log.info(f"msfrpcd connected ({host}:{port})")
                return True
            except Exception as e:
                log.debug(f"msf connect attempt {attempt + 1}: {e}")
                time.sleep(1.5)
        return False

    def search(self, query: str) -> list:
        if not self.client:
            return []
        try:
            res = self.client.modules.search(query)
            return res if isinstance(res, list) else []
        except Exception as e:
            log.debug(f"msf search failed: {e}")
            return []

    def module_info(self, module: str) -> dict:
        if not self.client:
            return {}
        parts = module.split("/")
        if len(parts) < 2:
            return {}
        mtype, mname = parts[0], "/".join(parts[1:])
        try:
            mod = self.client.modules.use(mtype, mname)
            return {
                "name": getattr(mod, "modulename", module),
                "rank": getattr(mod, "rank", ""),
                "description": getattr(mod, "description", ""),
                "references": getattr(mod, "references", []),
                "options": dict(getattr(mod, "options", {})),
            }
        except Exception as e:
            log.debug(f"module_info {module}: {e}")
            return {}

    def sessions(self) -> dict:
        if not self.client:
            return {}
        try:
            return self.client.sessions.list
        except Exception:
            return {}
