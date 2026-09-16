from __future__ import annotations
import sqlite3
from pathlib import Path
from typing import Optional

from core.state import RunState


SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    target TEXT,
    started TEXT,
    finished TEXT,
    state TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT,
    title TEXT,
    severity TEXT,
    source TEXT,
    cve TEXT,
    score REAL
);
CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT,
    username TEXT,
    password TEXT,
    service TEXT,
    host TEXT,
    valid INTEGER
);
CREATE TABLE IF NOT EXISTS flags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT,
    name TEXT,
    value TEXT,
    path TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_creds_run ON credentials(run_id);
"""


class Database:
    def __init__(self, path: Path | str = "./loot/chainpwn.db"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def save_state(self, state: RunState) -> None:
        target = state.target.host if state.target else None
        self.conn.execute(
            "INSERT OR REPLACE INTO runs(run_id,target,started,finished,state) VALUES(?,?,?,?,?)",
            (state.run_id, target, state.started, state.finished, state.to_json()),
        )
        self.conn.execute("DELETE FROM findings WHERE run_id=?", (state.run_id,))
        self.conn.execute("DELETE FROM credentials WHERE run_id=?", (state.run_id,))
        self.conn.execute("DELETE FROM flags WHERE run_id=?", (state.run_id,))
        for f in state.findings:
            self.conn.execute(
                "INSERT INTO findings(run_id,title,severity,source,cve,score) VALUES(?,?,?,?,?,?)",
                (state.run_id, f.title, f.severity.value, f.source, f.cve, f.score),
            )
        for c in state.credentials:
            self.conn.execute(
                "INSERT INTO credentials(run_id,username,password,service,host,valid) VALUES(?,?,?,?,?,?)",
                (state.run_id, c.username, c.password, c.service, c.host, int(c.valid)),
            )
        for fl in state.flags:
            self.conn.execute(
                "INSERT INTO flags(run_id,name,value,path) VALUES(?,?,?,?)",
                (state.run_id, fl.name, fl.value, fl.path),
            )
        self.conn.commit()

    def load_state(self, run_id: str) -> Optional[RunState]:
        row = self.conn.execute("SELECT state FROM runs WHERE run_id=?", (run_id,)).fetchone()
        if not row:
            return None
        return RunState.from_json(row[0])

    def close(self) -> None:
        self.conn.close()
