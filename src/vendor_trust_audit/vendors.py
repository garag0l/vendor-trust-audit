"""Resolve AWS account ids to vendor names using a vendored, dated snapshot of fwdcloudsec/known_aws_accounts."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from pathlib import Path


@lru_cache(maxsize=1)
def snapshot() -> dict:
    return json.loads(resources.files(__package__).joinpath("data/known_aws_accounts.json").read_text(encoding="utf-8"))


def load_extra(path: str | Path) -> dict[str, str]:
    """User-supplied vendor map: JSON object {"123456789012": "Vendor name", ...}."""
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    return {str(k).zfill(12): str(v) for k, v in data.items()}


def resolve(account: str, extra: dict[str, str] | None = None) -> tuple[str, str]:
    """Return (name, source). Name is "" when unknown."""
    if extra and account in extra:
        return extra[account], "user vendor map"
    hit = snapshot()["accounts"].get(account)
    if hit:
        return hit["name"], hit.get("source", "")
    return "", ""
