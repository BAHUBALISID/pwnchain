from __future__ import annotations

from core.logger import log
from core.state import Service, ServiceState, Target
from wrappers.base import BaseTool


class NmapTool(BaseTool):
    name = "nmap"

    async def scan(self, target: Target, udp: bool = False) -> list[Service]:
        flags = list(self.cfg.get("nmap", "udp_flags" if udp else "default_flags", default=[]) or [])
        args = flags + [target.host]
        code, out, err = await self.run_cmd(args, timeout=1800)
        if code != 0:
            log.warning(f"nmap rc={code}: {err[:200]}")
        return self._parse(out)

    def _parse(self, xml: str) -> list[Service]:
        services: list[Service] = []
        if not xml.strip():
            return services
        try:
            from lxml import etree
            root = etree.fromstring(xml.encode())
        except Exception:
            return services

        for host in root.findall("host"):
            for port in host.findall(".//port"):
                state_el = port.find("state")
                state_str = state_el.get("state") if state_el is not None else "open"
                if state_str != "open":
                    continue
                svc_el = port.find("service")
                name = svc_el.get("name", "") if svc_el is not None else ""
                product = svc_el.get("product", "") if svc_el is not None else ""
                version = svc_el.get("version", "") if svc_el is not None else ""

                scripts: dict[str, str] = {}
                banner_lines: list[str] = []
                for sc in port.findall("script"):
                    sid = sc.get("id", "")
                    soutput = sc.get("output", "")
                    scripts[sid] = soutput
                    banner_lines.append(soutput)

                try:
                    pnum = int(port.get("portid"))
                except (TypeError, ValueError):
                    continue

                try:
                    state_enum = ServiceState(state_str)
                except ValueError:
                    state_enum = ServiceState.OPEN

                services.append(Service(
                    port=pnum,
                    proto=port.get("protocol", "tcp"),
                    name=name,
                    product=product,
                    version=version,
                    state=state_enum,
                    banner="\n".join(banner_lines).strip(),
                    scripts=scripts,
                ))
        return services
