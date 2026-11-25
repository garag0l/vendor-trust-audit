"""Load roles from `aws iam get-account-authorization-details` output (file or live)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote

from .policy import as_list


def _doc(d) -> dict:
    """Policy documents arrive as dicts (boto3), JSON strings, or URL-encoded JSON (raw API / some CLI paths)."""
    if isinstance(d, dict):
        return d
    if isinstance(d, str) and d.strip():
        s = d if d.lstrip().startswith("{") else unquote(d)
        return json.loads(s)
    return {"Statement": []}


def _statements(name: str, doc) -> list[tuple[str, dict]]:
    return [(name, st) for st in as_list(_doc(doc).get("Statement")) if isinstance(st, dict)]


def parse_time(v) -> datetime | None:
    if v is None or v == "":
        return None
    if isinstance(v, datetime):
        return v
    s = str(v).replace("Z", "+00:00")
    return datetime.fromisoformat(s)


@dataclass
class Role:
    name: str
    arn: str
    trust: dict
    statements: list[tuple[str, dict]] = field(default_factory=list)
    boundary: list[tuple[str, dict]] | None = None
    last_used: datetime | None = None
    last_used_region: str = ""
    created: datetime | None = None
    path: str = "/"
    source: str = ""  # input file the role came from

    @property
    def account(self) -> str:
        parts = self.arn.split(":")
        return parts[4] if len(parts) > 4 else ""

    @property
    def partition(self) -> str:
        parts = self.arn.split(":")
        return parts[1] if len(parts) > 1 else "aws"


def load_gaad(data: dict, source: str = "") -> list[Role]:
    managed: dict[str, dict] = {}
    for p in data.get("Policies", []):
        default = next((v for v in p.get("PolicyVersionList", []) if v.get("IsDefaultVersion")), None)
        if default:
            managed[p["Arn"]] = {"name": p.get("PolicyName", p["Arn"]), "doc": default.get("Document")}

    unresolved: set[str] = set()

    def attached(lst) -> list[tuple[str, dict]]:
        out = []
        for a in lst or []:
            m = managed.get(a.get("PolicyArn"))
            if m:
                out += _statements(m["name"], m["doc"])
            else:
                unresolved.add(a.get("PolicyArn", "?"))
        return out

    roles: list[Role] = []
    for r in data.get("RoleDetailList", []):
        st = attached(r.get("AttachedManagedPolicies"))
        for ip in r.get("RolePolicyList", []):
            st += _statements(ip["PolicyName"], ip.get("PolicyDocument"))
        pb = r.get("PermissionsBoundary")
        boundary = None
        if pb:
            m = managed.get(pb.get("PermissionsBoundaryArn"))
            # An unresolvable boundary is treated as absent (over-reports reach rather than hiding it).
            boundary = _statements(f"boundary:{m['name']}", m["doc"]) if m else None
        lu = r.get("RoleLastUsed") or {}
        roles.append(
            Role(
                name=r["RoleName"],
                arn=r["Arn"],
                trust=_doc(r.get("AssumeRolePolicyDocument") or {}),
                statements=st,
                boundary=boundary,
                last_used=parse_time(lu.get("LastUsedDate")),
                last_used_region=lu.get("Region", ""),
                created=parse_time(r.get("CreateDate")),
                path=r.get("Path", "/"),
                source=source,
            )
        )
    return roles


def from_file(path: str | Path) -> list[Role]:
    return load_gaad(json.loads(Path(path).read_text(encoding="utf-8-sig")), source=str(path))
