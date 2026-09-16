from __future__ import annotations
import asyncio
import socket
import subprocess
from typing import Optional


def _ip_addr_show(iface: str) -> Optional[str]:
    try:
        out = subprocess.check_output(
            ["ip", "-4", "addr", "show", iface],
            stderr=subprocess.DEVNULL,
        ).decode()
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1].split("/")[0]
    except Exception:
        pass
    return None


def detect_tun_ip() -> Optional[str]:
    for iface in ("tun0", "tun1", "tap0"):
        ip = _ip_addr_show(iface)
        if ip:
            return ip
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


async def port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        _, w = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout,
        )
        w.close()
        return True
    except Exception:
        return False


async def scan_ports(host: str, ports: list[int], timeout: float = 1.5) -> list[int]:
    tasks = [port_open(host, p, timeout) for p in ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [p for p, ok in zip(ports, results) if ok is True]
