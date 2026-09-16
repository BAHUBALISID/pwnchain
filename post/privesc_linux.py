from __future__ import annotations
from core.state import Finding, Severity, Session


PRIVESC_CHECKS = {
    "sudo_nopasswd": "sudo -n -l 2>/dev/null",
    "suid_find": "find / -perm -4000 -type f 2>/dev/null",
    "caps": "getcap -r / 2>/dev/null",
    "cron": "cat /etc/crontab /etc/cron.d/* 2>/dev/null",
    "docker_group": "id | grep docker",
    "writable_etc": "find /etc -writable 2>/dev/null",
}

GTFOBINS_SUID = {
    "nmap", "vim", "find", "bash", "sh", "more", "less", "awk",
    "perl", "python", "python3", "cp", "mv", "nano", "env", "tar", "gzip",
}


class LinuxPrivesc:
    def __init__(self, handler):
        self.handler = handler

    async def run(self, session: Session, state) -> list:
        findings: list[Finding] = []
        for name, cmd in PRIVESC_CHECKS.items():
            out = await self.handler.send(session, cmd)
            if not out.strip():
                continue
            if name == "suid_find":
                for line in out.splitlines():
                    for b in GTFOBINS_SUID:
                        if line.rstrip().endswith("/" + b):
                            findings.append(Finding(
                                title=f"SUID {b} (gtfobins)",
                                severity=Severity.HIGH,
                                source="privesc",
                                target=session.host,
                                evidence=line.strip(),
                            ))
            elif name == "sudo_nopasswd":
                if "NOPASSWD" in out:
                    findings.append(Finding(
                        title="sudo NOPASSWD entry",
                        severity=Severity.HIGH,
                        source="privesc",
                        target=session.host,
                        evidence=out,
                    ))
        for f in findings:
            state.add_finding(f)
        return findings
