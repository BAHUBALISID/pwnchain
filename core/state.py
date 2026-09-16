from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import json
import uuid


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ServiceState(str, Enum):
    OPEN = "open"
    FILTERED = "filtered"
    CLOSED = "closed"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Service:
    port: int
    proto: str = "tcp"
    name: str = ""
    product: str = ""
    version: str = ""
    state: ServiceState = ServiceState.OPEN
    banner: str = ""
    scripts: dict = field(default_factory=dict)
    url: Optional[str] = None
    extra: dict = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.proto}/{self.port}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["state"] = self.state.value
        return d


@dataclass
class Credential:
    username: str
    password: str
    service: str = ""
    host: str = ""
    source: str = ""
    valid: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    title: str
    severity: Severity = Severity.INFO
    source: str = ""
    target: str = ""
    description: str = ""
    evidence: str = ""
    cve: Optional[str] = None
    edb_id: Optional[str] = None
    msf_module: Optional[str] = None
    nuclei_template: Optional[str] = None
    score: float = 0.0
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class Session:
    id: str
    host: str
    user: str = ""
    kind: str = "shell"
    lhost: str = ""
    lport: int = 0
    root: bool = False
    stable: bool = False
    started: str = field(default_factory=_now)
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Flag:
    name: str
    value: str
    path: str = ""
    collected: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Target:
    host: str
    scheme: str = "http"
    port: Optional[int] = None
    path: str = "/"
    is_ip: bool = False

    @classmethod
    def from_string(cls, s: str) -> "Target":
        scheme = "http"
        port = None
        path = "/"
        body = s
        if "://" in s:
            scheme, body = s.split("://", 1)
        if "/" in body:
            body, path = body.split("/", 1)
            path = "/" + path
        if ":" in body:
            host_part, p = body.rsplit(":", 1)
            if p.isdigit():
                body = host_part
                port = int(p)
        parts = body.split(".")
        is_ip = len(parts) == 4 and all(x.isdigit() for x in parts)
        return cls(host=body, scheme=scheme, port=port, path=path, is_ip=is_ip)

    @property
    def base_url(self) -> str:
        p = f":{self.port}" if self.port else ""
        return f"{self.scheme}://{self.host}{p}"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RunState:
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    target: Optional[Target] = None
    services: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    credentials: list = field(default_factory=list)
    sessions: list = field(default_factory=list)
    flags: list = field(default_factory=list)
    tool_outputs: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)
    started: str = field(default_factory=_now)
    finished: Optional[str] = None

    def add_service(self, svc: Service) -> None:
        for i, s in enumerate(self.services):
            if s.key == svc.key:
                self.services[i] = svc
                return
        self.services.append(svc)

    def add_finding(self, f: Finding) -> None:
        self.findings.append(f)

    def add_credential(self, c: Credential) -> None:
        self.credentials.append(c)

    def add_session(self, s: Session) -> None:
        self.sessions.append(s)

    def add_flag(self, f: Flag) -> None:
        self.flags.append(f)

    def to_json(self) -> str:
        data = {
            "run_id": self.run_id,
            "target": self.target.to_dict() if self.target else None,
            "services": [s.to_dict() for s in self.services],
            "findings": [f.to_dict() for f in self.findings],
            "credentials": [c.to_dict() for c in self.credentials],
            "sessions": [s.to_dict() for s in self.sessions],
            "flags": [f.to_dict() for f in self.flags],
            "tool_outputs": self.tool_outputs,
            "errors": self.errors,
            "started": self.started,
            "finished": self.finished,
        }
        return json.dumps(data, indent=2, default=str)

    @classmethod
    def from_json(cls, raw: str) -> "RunState":
        data = json.loads(raw)
        st = cls(run_id=data.get("run_id") or uuid.uuid4().hex[:12])
        if data.get("target"):
            st.target = Target(**data["target"])
        for s in data.get("services", []):
            s = dict(s)
            s["state"] = ServiceState(s.get("state", "open"))
            st.services.append(Service(**s))
        for f in data.get("findings", []):
            f = dict(f)
            f["severity"] = Severity(f.get("severity", "info"))
            st.findings.append(Finding(**f))
        for c in data.get("credentials", []):
            st.credentials.append(Credential(**c))
        for s in data.get("sessions", []):
            st.sessions.append(Session(**s))
        for f in data.get("flags", []):
            st.flags.append(Flag(**f))
        st.tool_outputs = data.get("tool_outputs", {}) or {}
        st.errors = data.get("errors", []) or []
        st.started = data.get("started", st.started)
        st.finished = data.get("finished")
        return st
