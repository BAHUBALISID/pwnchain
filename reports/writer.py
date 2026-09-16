from __future__ import annotations
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.state import RunState


TEMPLATE_DIR = Path(__file__).parent / "templates"


class ReportWriter:
    def __init__(self, loot_dir: Path):
        self.loot_dir = Path(loot_dir)
        self.loot_dir.mkdir(parents=True, exist_ok=True)
        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def render_all(self, state: RunState | None = None) -> None:
        if state is None:
            state = self._load_latest()
        if state is None:
            return
        ctx = {
            "state": state,
            "target": state.target.host if state.target else "?",
            "services": state.services,
            "findings": sorted(state.findings, key=lambda f: f.score, reverse=True),
            "credentials": state.credentials,
            "sessions": state.sessions,
            "flags": state.flags,
            "errors": state.errors,
        }
        md = self.env.get_template("writeup.md.j2").render(**ctx)
        (self.loot_dir / f"writeup_{state.run_id}.md").write_text(md)

        html = self.env.get_template("summary.html.j2").render(**ctx)
        (self.loot_dir / f"summary_{state.run_id}.html").write_text(html)

    def _load_latest(self) -> RunState | None:
        files = sorted(self.loot_dir.glob("state_*.json"))
        if not files:
            return None
        try:
            return RunState.from_json(files[-1].read_text())
        except Exception:
            return None
