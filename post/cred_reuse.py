from __future__ import annotations
import os
import tempfile

from core.state import Credential
from wrappers.hydra import HydraTool


class CredReuse:
    def __init__(self, cfg):
        self.cfg = cfg

    async def spray(
        self,
        host: str,
        service: str,
        users: list[str],
        passwords: list[str],
        port: int | None = None,
        state=None,
    ) -> list[dict]:
        with tempfile.NamedTemporaryFile("w+", delete=False) as uf:
            uf.write("\n".join(users))
            upath = uf.name
        with tempfile.NamedTemporaryFile("w+", delete=False) as pf:
            pf.write("\n".join(passwords))
            ppath = pf.name

        try:
            h = HydraTool(self.cfg)
            hits = await h.brute(service, host, upath, ppath, port=port)
            if state and hits:
                for hit in hits:
                    state.add_credential(Credential(
                        username=hit["username"],
                        password=hit["password"],
                        service=service,
                        host=host,
                        source="hydra",
                        valid=True,
                    ))
            return hits
        finally:
            os.unlink(upath)
            os.unlink(ppath)
