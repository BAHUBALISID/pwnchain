from __future__ import annotations
from core.logger import log
from core.state import Session


class ShellStabilizer:
    def __init__(self, handler):
        self.handler = handler

    async def stabilize(self, session: Session) -> bool:
        cmds = [
            "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
            "python -c 'import pty;pty.spawn(\"/bin/bash\")'",
            "script -qc /bin/bash /dev/null",
        ]
        for c in cmds:
            out = await self.handler.send(session, c)
            if "bash" in out.lower() or "$" in out:
                session.stable = True
                log.info(f"Stabilized shell {session.id}")
                return True
        return False
