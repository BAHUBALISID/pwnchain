from __future__ import annotations
from core.logger import log
from core.state import Finding


class Applicability:
    def __init__(self, cfg):
        self.cfg = cfg

    def check(self, finding: Finding, state) -> bool:
        if finding.source == "metasploit" and not finding.msf_module:
            return False
        if finding.source == "nuclei" and not finding.nuclei_template:
            return False
        if finding.source == "searchsploit" and finding.edb_id and not finding.evidence:
            log.debug(f"EDB without path, skipping: {finding.title}")
            return False
        return True
