from __future__ import annotations
import asyncio
import socket
import uuid
from typing import Optional

from core.logger import log
from core.state import Session
from utils.net_utils import detect_tun_ip


class ShellHandler:
    def __init__(self, cfg):
        self.cfg = cfg
        self.sessions: list[Session] = []
        self._streams: dict[str, tuple] = {}
        self._server: Optional[asyncio.AbstractServer] = None
        self._queue: asyncio.Queue = asyncio.Queue()
        self.lport = self._pick_lport()
        self.lhost = detect_tun_ip() or "0.0.0.0"

    def _pick_lport(self) -> int:
        start = int(self.cfg.get("shell", "lport_start", default=4444))
        end = int(self.cfg.get("shell", "lport_end", default=4500))
        for p in range(start, end + 1):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind(("0.0.0.0", p))
                    return p
                except OSError:
                    continue
        return start

    async def start_listener(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, "0.0.0.0", self.lport,
        )
        log.info(f"Shell listener on {self.lhost}:{self.lport}")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername") or ("?", 0)
        log.info(f"Shell connection from {peer}")
        sid = uuid.uuid4().hex[:8]
        sess = Session(id=sid, host=peer[0], lhost=self.lhost, lport=self.lport)
        self.sessions.append(sess)
        self._streams[sid] = (reader, writer)
        await self._queue.put(sess)

    async def wait_for_session(self, timeout: int = 45) -> Optional[Session]:
        try:
            return await asyncio.wait_for(self._queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            log.warning("No shell callback within timeout")
            return None

    async def send(self, session: Session, command: str, read_timeout: float = 10.0) -> str:
        streams = self._streams.get(session.id)
        if not streams:
            return ""
        reader, writer = streams
        try:
            writer.write((command + "\n").encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(65536), timeout=read_timeout)
            return data.decode(errors="replace")
        except asyncio.TimeoutError:
            return ""
        except Exception as e:
            log.debug(f"send failed on {session.id}: {e}")
            return ""

    def close_async(self) -> None:
        async def _close():
            for reader, writer in self._streams.values():
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
            if self._server:
                self._server.close()
                try:
                    await self._server.wait_closed()
                except Exception:
                    pass
        try:
            loop = asyncio.get_event_loop()
            loop.create_task(_close())
        except Exception:
            pass
