"""Checks VTA-001..006 over roles that outside accounts can assume."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from .gaad import Role
from .policy import Reach, reach
from .trust import TrustGrant, external_grants
from .vendors import resolve

SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

WIZ = "https://www.wiz.io/blog/qubole-cross-account-access-abused-in-the-wild"
AWS_EXTID = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html"
AWS_KEYS = "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html"

# What an attacker holding the vendor's identity can read or pivot to (the Qubole harvesting set).
REACH_CLASSES: dict[str, tuple[str, ...]] = {
    "secretsmanager": ("secretsmanager:GetSecretValue",),
    "ssm-parameters": ("ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"),
    "lambda-env": ("lambda:GetFunctionConfiguration", "lambda:GetFunction"),
    "kms-decrypt": ("kms:Decrypt",),
    "s3-read": ("s3:GetObject",),
    "pass-role": ("iam:PassRole",),
    "assume-role": ("sts:AssumeRole",),
}
SECRET_CLASSES = ("secretsmanager", "ssm-parameters", "lambda-env")


@dataclass
class Finding:
    id: str
    severity: str
    role: str  # role ARN
    vendor: str
    vendor_account: str
    title: str
    detail: str
    remediation: str
    conditional: bool = False
    source: str = ""
    refs: list[str] = field(default_factory=list)


@dataclass
class RoleReport:
    role: Role
    grants: list[TrustGrant]
    vendors: dict[str, str]  # account -> name ("" unknown)
    reach: dict[str, Reach]
    dormant: bool
    findings: list[Finding] = field(default_factory=list)

    @property
    def secret_classes(self) -> list[str]:
        return [c for c, r in self.reach.items() if r.allowed and _counts(c, r)]

    @property
    def worst(self) -> str:
        return max((f.severity for f in self.findings), key=SEV.__getitem__, default="info")


def _counts(cls: str, r: Reach) -> bool:
    # s3:GetObject and sts:AssumeRole only matter when they are not scoped to specific resources.
    return r.broad if cls in ("s3-read", "assume-role", "pass-role") else True


def role_reach(role: Role) -> dict[str, Reach]:
    out = {}
    for cls, actions in REACH_CLASSES.items():
        best: Reach | None = None
        for a in actions:
            r = reach(role.statements, role.boundary, a)
            if r.allowed and (best is None or (r.broad and not best.broad) or (best.conditional and not r.conditional)):
                best = r
        out[cls] = best or Reach(actions[0])
    return out


def _fmt_reach(rep: RoleReport) -> str:
    parts = []
    for c in rep.secret_classes:
        r = rep.reach[c]
        scope = "*" if r.broad else ", ".join(r.resources[:3]) + (" ..." if len(r.resources) > 3 else "")
        parts.append(f"{c} ({r.action} on {scope}{', conditional' if r.conditional else ''})")
    return "; ".join(parts)


def audit(
    roles: list[Role],
    *,
    now: datetime | None = None,
    dormant_days: int = 90,
    internal_accounts: set[str] | None = None,
    org_id: str | None = None,
    vendor_map: dict[str, str] | None = None,
) -> list[RoleReport]:
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(days=dormant_days)
    reports: list[RoleReport] = []
    for role in roles:
        grants = external_grants(role.trust, role.account, internal_accounts, org_id)
        if not grants:
            continue
        vendors = {g.account: resolve(g.account, vendor_map)[0] for g in grants}
        last = role.last_used
        if last is not None and last.tzinfo is None:
            last = last.replace(tzinfo=UTC)
        dormant = last is None or last < cutoff
        rep = RoleReport(role, grants, vendors, role_reach(role), dormant)
        _check_role(rep, dormant_days)
        reports.append(rep)
    _check_external_id_reuse(reports)
    for rep in reports:
        rep.findings.sort(key=lambda f: (-SEV[f.severity], f.id))
    reports.sort(key=lambda r: (-SEV[r.worst], r.role.arn))
    return reports


def _vendor_label(rep: RoleReport, g: TrustGrant) -> str:
    if g.account == "*":
        return "anyone"
    return rep.vendors.get(g.account) or "unknown external account"


def _who(rep: RoleReport, g: TrustGrant) -> str:
    name = rep.vendors.get(g.account)
    return f"{name}'s account ({g.account})" if name else f"account {g.account} (owner unknown)"


def _check_role(rep: RoleReport, dormant_days: int) -> None:
    role = rep.role
    secrets = [c for c in rep.secret_classes if c in SECRET_CLASSES]
    reach_txt = _fmt_reach(rep)
    add = rep.findings.append

    def f(id_, sev, g: TrustGrant | None, title, detail, fix, cond=False, refs=()):
        add(
            Finding(
                id_,
                sev,
                role.arn,
                _vendor_label(rep, g) if g else ", ".join(sorted({_vendor_label(rep, x) for x in rep.grants})),
                g.account if g else ",".join(sorted({x.account for x in rep.grants})),
                title,
                detail,
                fix,
                cond,
                role.source,
                list(refs),
            )
        )

    for g in rep.grants:
        label = _vendor_label(rep, g)
        # VTA-006 wildcard principal
        if g.kind == "wildcard":
            if g.has_conditions:
                f(
                    "VTA-006",
                    "high",
                    g,
                    'Trust policy allows any AWS principal (Principal "*"), restricted only by conditions',
                    f"Statement {g.statement_index} admits every AWS account; access depends entirely on conditions "
                    f"{sorted(k for kv in g.conditions.values() for k in kv)}.",
                    "Replace the wildcard with the specific vendor role ARN, and keep the conditions.",
                    refs=[AWS_EXTID],
                )
            else:
                f(
                    "VTA-006",
                    "critical",
                    g,
                    "Trust policy allows any AWS principal to assume the role, with no conditions",
                    f'Statement {g.statement_index} has Principal "*" and no Condition: any AWS account can assume this role.',
                    "Restrict the Principal to the vendor's role ARN and require sts:ExternalId plus a network or org condition.",
                )
            continue
        # VTA-001 vendor identity
        if rep.vendors.get(g.account):
            f(
                "VTA-001",
                "info",
                g,
                f"Role is assumable by vendor {label} ({g.account})",
                f"Principal {g.principal} resolves to {label} via known_aws_accounts.",
                "Confirm the integration is still in use and owned; record it in your third-party inventory.",
            )
        else:
            f(
                "VTA-001",
                "medium",
                g,
                f"Role is assumable by an unknown external account ({g.account})",
                f"Principal {g.principal} is not in your account, your --internal-accounts, or the known-vendor list.",
                "Identify the owner of this account. If nobody can, remove the trust. Add known partners with --vendor-map.",
            )
        # VTA-003 root principal
        if g.kind in ("root", "account"):
            f(
                "VTA-003",
                "medium",
                g,
                "Trust names the vendor account root, not a specific vendor role",
                f"{g.principal} lets any IAM user or role in {_who(rep, g)} that is allowed sts:AssumeRole assume this role. "
                "In the Qubole incident, two compromised vendor IAM users were enough.",
                f"Set Principal to the vendor's integration role ARN (arn:{role.partition}:iam::{g.account}:role/<vendor-role>) "
                "or add an aws:PrincipalArn condition.",
                refs=[WIZ],
            )
        # VTA-004 ExternalId as the only control
        if not g.narrowing:
            if g.external_ids:
                sev = "high" if secrets else "medium"
                f(
                    "VTA-004",
                    sev,
                    g,
                    "sts:ExternalId is the only thing restricting who can assume the role",
                    "There is no aws:SourceIp, aws:SourceVpce, aws:PrincipalOrgID, aws:PrincipalArn or aws:SourceIdentity "
                    "condition. External IDs are logged in plaintext in CloudTrail and stored by the vendor; every malicious "
                    "AssumeRole in the Qubole incident presented the correct one.",
                    "Add aws:SourceIp (vendor egress ranges) or aws:PrincipalArn (vendor role) to the trust policy. "
                    "Wiz reports a SourceIp condition alone would have blocked every observed assumption.",
                    refs=[WIZ, AWS_KEYS],
                )
            else:
                sev = "high" if (secrets or g.kind in ("root", "account")) else "medium"
                f(
                    "VTA-004",
                    sev,
                    g,
                    "Cross-account trust has no sts:ExternalId and no narrowing condition"
                    + (" (ExternalId is only used in a negated operator)" if g.negated_external_id else ""),
                    f"Anyone in {_who(rep, g)} allowed to call sts:AssumeRole on this ARN can assume it, and the vendor can be "
                    "used as a confused deputy by its other customers.",
                    "Require a unique sts:ExternalId (StringEquals) and add aws:SourceIp or aws:PrincipalArn.",
                    refs=[AWS_EXTID],
                )
    # VTA-002 dormant
    if rep.dormant:
        when = role.last_used.date().isoformat() if role.last_used else "never (within the IAM tracking window)"
        sev = "high" if secrets else "medium"
        f(
            "VTA-002",
            sev,
            None,
            f"Vendor-assumable role is dormant (last used: {when})",
            f"No use in the last {dormant_days} days, but the trust is still live. Several Qubole victims' roles were dormant "
            "and still accepted the attacker.",
            "Delete the role, or remove the external principal from its trust policy until the integration is needed again.",
            refs=[WIZ],
        )
    # VTA-005 secret reach
    if rep.secret_classes:
        cond = any(rep.reach[c].conditional for c in rep.secret_classes)
        sev = "high" if secrets else "medium"
        if secrets and (rep.dormant or any(not g.narrowing for g in rep.grants)):
            sev = "critical" if not cond else "high"
        f(
            "VTA-005",
            sev,
            None,
            "Vendor-assumable role can read secrets or pivot",
            f"Effective permissions (identity policies after boundary and explicit denies): {reach_txt}.",
            "Scope the role to the exact resources the integration needs; remove secretsmanager/ssm/lambda read, "
            "kms:Decrypt, wildcard s3:GetObject and iam:PassRole unless the vendor's documentation requires them.",
            cond,
            refs=[WIZ],
        )


def _check_external_id_reuse(reports: list[RoleReport]) -> None:
    by_id: dict[str, list[tuple[RoleReport, TrustGrant]]] = defaultdict(list)
    for rep in reports:
        for g in rep.grants:
            for x in set(g.external_ids):
                by_id[x].append((rep, g))
    for ext, uses in by_id.items():
        roles = {r.role.arn for r, _ in uses}
        accounts = {g.account for _, g in uses}
        if len(roles) < 2:
            continue
        cross_vendor = len(accounts) > 1
        masked = ext[:3] + "…" if len(ext) > 6 else "…"
        for rep, g in uses:
            others = sorted(roles - {rep.role.arn})
            rep.findings.append(
                Finding(
                    "VTA-004",
                    "medium" if cross_vendor else "low",
                    rep.role.arn,
                    _vendor_label(rep, g),
                    g.account,
                    "Same sts:ExternalId is reused " + ("across different vendor accounts" if cross_vendor else "across roles"),
                    f"ExternalId {masked} also appears on {len(others)} other role(s): {', '.join(others[:5])}"
                    + (" ..." if len(others) > 5 else "")
                    + ". One leaked value opens all of them.",
                    "Use a unique, unguessable ExternalId per role and per vendor.",
                    source=rep.role.source,
                    refs=[AWS_EXTID],
                )
            )
