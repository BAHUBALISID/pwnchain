from __future__ import annotations
from core.state import Finding, Severity, Session


class WindowsPrivesc:
    def __init__(self, handler):
        self.handler = handler

    async def run(self, session: Session, state) -> list:
        findings: list[Finding] = []
        out = await self.handler.send(session, "whoami /priv")
        if "SeImpersonatePrivilege" in out:
            findings.append(Finding(
                title="SeImpersonatePrivilege enabled",
                severity=Severity.HIGH,
                source="privesc",
                target=session.host,
                evidence=out,
            ))
        for f in findings:
            state.add_finding(f)
        return findings
