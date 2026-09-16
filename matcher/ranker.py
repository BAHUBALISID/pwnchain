from __future__ import annotations
from core.state import Finding, Severity


SEV_WEIGHT = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 3.0,
    Severity.INFO: 1.0,
}

SOURCE_WEIGHT = {
    "metasploit": 4.0,
    "nuclei": 3.5,
    "searchsploit": 2.5,
}


class Ranker:
    def rank(self, findings: list[Finding]) -> list[Finding]:
        for f in findings:
            f.score = self._score(f)
        findings.sort(key=lambda x: x.score, reverse=True)
        return findings

    def _score(self, f: Finding) -> float:
        score = SEV_WEIGHT.get(f.severity, 1.0)
        score += SOURCE_WEIGHT.get(f.source, 1.0)
        if f.msf_module:
            score += 3.0
            if f.msf_module.startswith("exploit/"):
                score += 2.0
        if f.edb_id:
            score += 1.5
        if f.nuclei_template:
            score += 1.0
        if f.cve:
            score += 1.0
        return round(score, 3)
