from __future__ import annotations
import ipaddress
import re
from urllib.parse import urlparse

from core.exceptions import ValidationError


DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$")


def validate_target(target: str) -> str:
    if not target or not isinstance(target, str):
        raise ValidationError("target is required")
    body = target
    if "://" in body:
        parsed = urlparse(body)
        body = parsed.hostname or ""
    else:
        body = body.split("/", 1)[0]
    if ":" in body:
        body = body.rsplit(":", 1)[0]

    try:
        ipaddress.ip_address(body)
        return target
    except ValueError:
        pass

    if DOMAIN_RE.match(body):
        return target
    raise ValidationError(f"invalid target: {target}")


def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def is_url(s: str) -> bool:
    return s.startswith(("http://", "https://"))
