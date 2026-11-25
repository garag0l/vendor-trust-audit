"""Parse role trust policies into the external principals that can assume the role."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .policy import action_matches, as_list

ASSUME_ACTIONS = ("sts:AssumeRole",)
ACCOUNT_RX = re.compile(r"^\d{12}$")
ARN_RX = re.compile(r"^arn:(aws[a-z-]*):(iam|sts)::(\d{12}):(.+)$")

# Condition keys that bind the caller to a network location, organization, or specific identity.
# Any one of these (with a positive operator) means the trust is narrower than "whoever knows the ExternalId".
NARROWING_KEYS = {
    "aws:sourceip": "network",
    "aws:sourcevpce": "network",
    "aws:sourcevpc": "network",
    "aws:principalorgid": "organization",
    "aws:principalorgpaths": "organization",
    "aws:principalarn": "identity",
    "aws:sourceidentity": "identity",
    "sts:sourceidentity": "identity",
    "aws:userid": "identity",
    "aws:principaltag": "identity",
}
NEGATIVE_OPS = ("stringnot", "arnnot", "notipaddress", "null")


@dataclass
class TrustGrant:
    """One external principal admitted by one Allow statement of a trust policy."""

    principal: str  # as written in the policy
    account: str  # 12-digit account id, or "*"
    kind: str  # root | role | user | assumed-role | account | wildcard | unique-id
    statement_index: int
    sid: str = ""
    external_ids: list[str] = field(default_factory=list)
    narrowing: dict[str, list[str]] = field(default_factory=dict)  # condition key -> values
    conditions: dict = field(default_factory=dict)
    negated_external_id: bool = False

    @property
    def has_conditions(self) -> bool:
        return bool(self.conditions)


def _principal_kind(p: str) -> tuple[str, str]:
    if p == "*":
        return "*", "wildcard"
    if ACCOUNT_RX.match(p):
        return p, "account"
    m = ARN_RX.match(p)
    if m:
        rest = m.group(4)
        if rest == "root":
            return m.group(3), "root"
        if rest.startswith("assumed-role/"):
            return m.group(3), "assumed-role"
        return m.group(3), rest.split("/", 1)[0]
    if p.startswith(("AROA", "AIDA")):
        # A principal that was deleted after the policy was written is shown as its unique id.
        return "?", "unique-id"
    return "?", "unknown"


def _external_ids(cond: dict) -> tuple[list[str], bool]:
    ids, negated = [], False
    for op, kv in (cond or {}).items():
        for key, vals in (kv or {}).items():
            if key.lower() != "sts:externalid":
                continue
            if op.lower().startswith(NEGATIVE_OPS):
                negated = True
                continue
            ids += [str(v) for v in as_list(vals)]
    return ids, negated


def _narrowing(cond: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for op, kv in (cond or {}).items():
        op_l = op.lower()
        if op_l.startswith(NEGATIVE_OPS) or op_l.endswith("ifexists"):
            # "...IfExists" passes when the key is absent, so it does not bind the caller.
            continue
        for key, vals in (kv or {}).items():
            base = key.lower().split("/", 1)[0]
            if base in NARROWING_KEYS:
                out[key] = [str(v) for v in as_list(vals)]
    return out


def external_grants(
    trust: dict, own_account: str, internal_accounts: set[str] | None = None, org_id: str | None = None
) -> list[TrustGrant]:
    """Allow statements for sts:AssumeRole that admit an AWS principal outside `own_account` (and `internal_accounts`).

    Service and federated principals are ignored (they are not cross-account vendor trust).
    A statement narrowed with aws:PrincipalOrgID equal to `org_id` is treated as internal.
    """
    internal = {own_account} | set(internal_accounts or ())
    out: list[TrustGrant] = []
    for i, st in enumerate(as_list(trust.get("Statement"))):
        if not isinstance(st, dict) or st.get("Effect") != "Allow":
            continue
        actions = as_list(st.get("Action"))
        if "NotAction" in st:
            if any(action_matches(p, "sts:AssumeRole") for p in as_list(st["NotAction"])):
                continue
        elif not any(action_matches(a, "sts:AssumeRole") for a in actions):
            continue
        pr = st.get("Principal")
        if pr == "*":
            aws = ["*"]
        elif isinstance(pr, dict):
            aws = [str(x) for x in as_list(pr.get("AWS"))]
        else:
            aws = []
        if not aws:
            continue
        cond = st.get("Condition") or {}
        narrowing = _narrowing(cond)
        if org_id:
            orgs = [v for k, v in narrowing.items() if k.lower() == "aws:principalorgid"]
            if any(org_id in vals for vals in orgs):
                continue
        ext, neg = _external_ids(cond)
        for p in aws:
            acct, kind = _principal_kind(p)
            if acct in internal:
                continue
            out.append(
                TrustGrant(
                    principal=p,
                    account=acct,
                    kind=kind,
                    statement_index=i,
                    sid=str(st.get("Sid", "")),
                    external_ids=ext,
                    narrowing=narrowing,
                    conditions=cond,
                    negated_external_id=neg,
                )
            )
    return out
