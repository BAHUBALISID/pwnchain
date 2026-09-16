from __future__ import annotations
from pathlib import Path
from typing import Any, Optional
import yaml

CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"


class Config:
    def __init__(self, settings: dict, wordlists: dict):
        self.settings = settings or {}
        self.wordlists = wordlists or {}

    def get(self, *keys: str, default: Any = None) -> Any:
        node: Any = self.settings
        for k in keys:
            if not isinstance(node, dict) or k not in node:
                return default
            node = node[k]
        return node

    def stage(self, name: str) -> dict:
        return (self.wordlists.get("stages") or {}).get(name, {}) or {}

    def preset(self, name: str) -> dict:
        return (self.wordlists.get("presets") or {}).get(name, {}) or {}

    def resolve_lists(self, stage: str, preset: str) -> tuple[str, list]:
        stage_cfg = self.stage(stage)
        preset_cfg = self.preset(preset).get(stage, {}) or {}
        strategy = preset_cfg.get("strategy", "fallback")
        names = preset_cfg.get("lists", [])
        all_lists = stage_cfg.get("lists", {}) or {}

        resolved = []
        for n in names:
            if n in all_lists:
                entry = dict(all_lists[n])
                entry["name"] = n
                entry.setdefault("threads", stage_cfg.get("threads", 40))
                entry.setdefault("priority", 100)
                entry.setdefault("enabled", True)
                resolved.append(entry)

        if not resolved:
            for k, v in all_lists.items():
                if v.get("enabled", True):
                    entry = dict(v)
                    entry["name"] = k
                    entry.setdefault("threads", stage_cfg.get("threads", 40))
                    entry.setdefault("priority", 100)
                    resolved.append(entry)

        resolved = [r for r in resolved if r.get("enabled", True) and r.get("path")]
        resolved.sort(key=lambda e: e.get("priority", 100))
        return strategy, resolved


def load_config(path: Optional[Path] = None) -> Config:
    base = Path(path).parent if path else CONFIG_DIR
    settings_path = Path(path) if path else (CONFIG_DIR / "settings.yaml")
    wordlists_path = base / "wordlists.yaml"

    settings: dict = {}
    wordlists: dict = {}
    if settings_path.exists():
        with open(settings_path, "r") as f:
            settings = yaml.safe_load(f) or {}
    if wordlists_path.exists():
        with open(wordlists_path, "r") as f:
            wordlists = yaml.safe_load(f) or {}
    return Config(settings, wordlists)
