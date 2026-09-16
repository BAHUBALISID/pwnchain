from __future__ import annotations
import re


USER_PASS_PATTERNS = [
    re.compile(
        r"(?:user(?:name)?|login)\s*[:=]\s*['\"]?([\w.@-]+)['\"]?\s*[\n,;]\s*(?:pass(?:word)?|pwd)\s*[:=]\s*['\"]?([^\s'\"]+)",
        re.I,
    ),
    re.compile(r"([\w.@-]+):([^\s:]+)@"),
    re.compile(
        r"DB_USER(?:NAME)?\s*=\s*([^\s]+)\s*\nDB_PASS(?:WORD)?\s*=\s*([^\s]+)",
        re.I,
    ),
]

VERSION_PATTERNS = [
    re.compile(r"([A-Za-z][\w-]+)[/ ](\d+\.\d+(?:\.\d+)?)"),
    re.compile(r"Server:\s*([\w-]+)/(\d+\.\d+(?:\.\d+)?)"),
]


def extract_user_pass(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for pat in USER_PASS_PATTERNS:
        for m in pat.findall(text):
            if isinstance(m, tuple) and len(m) == 2:
                out.append((m[0], m[1]))
    return out


def extract_product_version(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for pat in VERSION_PATTERNS:
        for m in pat.findall(text):
            out.append((m[0], m[1]))
    return out
