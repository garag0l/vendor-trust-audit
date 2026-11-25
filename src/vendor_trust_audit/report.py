"""Text, JSON, SARIF and CloudTrail-query output."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict

from . import __version__
from .checks import SEV, Finding, RoleReport
from .vendors import snapshot

RULES = {
    "VTA-001": ("vendor-identity", "Role assumable by an external account (named vendor, or unknown)"),
    "VTA-002": ("dormant-trust", "Vendor-assumable role has not been used recently"),
    "VTA-003": ("root-principal", "Trust names the vendor account root instead of a specific role"),
    "VTA-004": ("external-id-only", "ExternalId is missing, reused, or the only restriction on the trust"),
    "VTA-005": ("secret-reach", "Vendor-assumable role can read secrets or pivot"),
    "VTA-006": ("wildcard-principal", "Trust policy admits any AWS principal"),
}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}


def all_findings(reports: list[RoleReport]) -> list[Finding]:
    out = [f for r in reports for f in r.findings]
    out.sort(key=lambda f: (-SEV[f.severity], f.id, f.role))
    return out


def _last_used(r: RoleReport) -> str:
    return r.role.last_used.date().isoformat() if r.role.last_used else "never"


def text(reports: list[RoleReport], *, color: bool = False, min_severity: str = "info") -> str:
    def c(code, s):
        return f"\033[{code}m{s}\033[0m" if color else s

    col = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "2"}
    lines = [
        c("1", f"vendor-trust-audit {__version__}") + c("2", f"  (vendor list: known_aws_accounts@{snapshot()['commit'][:12]})"),
        "",
    ]
    if not reports:
        lines.append("No roles are assumable by principals outside the account.")
        return "\n".join(lines)
    by_vendor: dict[tuple[str, str], list[RoleReport]] = defaultdict(list)
    for r in reports:
        for g in r.grants:
            name = "anyone" if g.account == "*" else (r.vendors.get(g.account) or "UNKNOWN")
            key = (name, g.account)
            if r not in by_vendor[key]:
                by_vendor[key].append(r)
    lines.append(c("1", "Vendors with access"))
    for (name, acct), rs in sorted(by_vendor.items(), key=lambda kv: (-max(SEV[x.worst] for x in kv[1]), kv[0])):
        where = 'Principal "*"' if acct == "*" else acct
        lines.append(f"  {c('1', name)} ({where}): {len(rs)} role(s)")
        for r in rs:
            reach = ",".join(r.secret_classes) or "-"
            lines.append(
                f"    {c(col[r.worst], f'{r.worst.upper():<8}')} {r.role.name:<40} last used {_last_used(r):<10}  reach: {reach}"
            )
    lines.append("")
    shown = [f for f in all_findings(reports) if SEV[f.severity] >= SEV[min_severity]]
    for f in shown:
        lines.append(
            f"{c(col[f.severity], '[' + f.severity.upper() + ']')} {f.id} {c('1', f.role)}"
            + (c("2", "  (conditional)") if f.conditional else "")
        )
        lines.append(f"       {f.title}")
        lines.append(f"       {f.detail}")
        lines.append(c("32", f"       fix: {f.remediation}"))
    allf = all_findings(reports)
    counts = {s: sum(1 for f in allf if f.severity == s) for s in SEV}
    lines += [
        "",
        c(
            "1",
            f"{len(reports)} vendor-assumable role(s), {len(allf)} finding(s): {counts['critical']} critical, {counts['high']} high, "
            f"{counts['medium']} medium, {counts['low']} low, {counts['info']} info",
        ),
    ]
    return "\n".join(lines)


def as_json(reports: list[RoleReport]) -> dict:
    return {
        "tool": "vendor-trust-audit",
        "version": __version__,
        "vendor_snapshot": {k: snapshot()[k] for k in ("upstream", "commit", "generated")},
        "roles": [
            {
                "arn": r.role.arn,
                "name": r.role.name,
                "account": r.role.account,
                "last_used": r.role.last_used.isoformat() if r.role.last_used else None,
                "dormant": r.dormant,
                "worst": r.worst,
                "principals": [
                    {
                        "principal": g.principal,
                        "account": g.account,
                        "vendor": r.vendors.get(g.account) or None,
                        "kind": g.kind,
                        "has_external_id": bool(g.external_ids),
                        "narrowing_conditions": sorted(g.narrowing),
                    }
                    for g in r.grants
                ],
                "reach": {
                    c: {"resources": list(x.resources), "conditional": x.conditional} for c, x in r.reach.items() if x.allowed
                },
                "readable_secret_classes": r.secret_classes,
            }
            for r in reports
        ],
        "findings": [asdict(f) for f in all_findings(reports)],
    }


def sarif(reports: list[RoleReport]) -> dict:
    results = []
    for f in all_findings(reports):
        results.append(
            {
                "ruleId": f.id,
                "level": SARIF_LEVEL[f.severity],
                "message": {"text": f"{f.title}: {f.role}. {f.detail} Fix: {f.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": (f.source or "iam").replace("\\", "/")},
                            "region": {"startLine": 1},
                        },
                        "logicalLocations": [{"fullyQualifiedName": f.role, "kind": "resource"}],
                    }
                ],
                "partialFingerprints": {"vta/v1": f"{f.id}:{f.role}:{f.vendor_account}:{f.title}"},
                "properties": {
                    "severity": f.severity,
                    "vendor": f.vendor,
                    "vendorAccount": f.vendor_account,
                    "conditional": f.conditional,
                },
            }
        )
    rules = [
        {
            "id": rid,
            "name": name,
            "shortDescription": {"text": desc},
            "helpUri": "https://github.com/garag0l/vendor-trust-audit#checks",
            "properties": {"tags": ["security", "aws", "iam", "third-party"]},
        }
        for rid, (name, desc) in RULES.items()
    ]
    # GitHub code scanning reads security-severity from the rule; use the worst seen per rule.
    worst: dict[str, str] = {}
    for f in all_findings(reports):
        if f.id not in worst or SEV[f.severity] > SEV[worst[f.id]]:
            worst[f.id] = f.severity
    for r in rules:
        r["properties"]["security-severity"] = SECURITY_SEVERITY[worst.get(r["id"], "medium")]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vendor-trust-audit",
                        "version": __version__,
                        "informationUri": "https://github.com/garag0l/vendor-trust-audit",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def _sql_list(arns: list[str]) -> str:
    return ", ".join("'" + a.replace("'", "''") + "'" for a in arns)


def cloudtrail_queries(reports: list[RoleReport], since: str, min_severity: str = "medium") -> str:
    """IR scoping queries: who assumed the flagged roles since `since`, and what they read with the session."""
    arns = sorted({r.role.arn for r in reports if SEV[r.worst] >= SEV[min_severity]})
    if not arns:
        return "-- no roles at or above the chosen severity"
    lst = _sql_list(arns)
    harvest = _sql_list(
        [
            "GetSecretValue",
            "BatchGetSecretValue",
            "GetParameter",
            "GetParameters",
            "GetParametersByPath",
            "GetFunction",
            "GetFunctionConfiguration",
            "Decrypt",
            "GetObject",
            "ListSecrets",
            "DescribeParameters",
            "ListFunctions",
        ]
    )
    since_sql = since.replace("'", "''")
    return f"""-- vendor-trust-audit {__version__}: IR scoping queries for {len(arns)} flagged role(s), since {since}
-- 1) CloudTrail Lake: every AssumeRole into the flagged roles (replace <event-data-store-id>)
SELECT eventTime, recipientAccountId, userIdentity.accountId AS caller_account, userIdentity.arn AS caller_arn,
       sourceIPAddress, userAgent, element_at(requestParameters, 'roleArn') AS role_arn,
       element_at(requestParameters, 'externalId') AS external_id, errorCode
FROM <event-data-store-id>
WHERE eventName = 'AssumeRole'
  AND element_at(requestParameters, 'roleArn') IN ({lst})
  AND eventTime >= '{since_sql}'
ORDER BY eventTime;

-- 2) CloudTrail Lake: what those sessions did next (secret harvesting pattern)
SELECT eventTime, eventSource, eventName, sourceIPAddress, userIdentity.arn AS session_arn, errorCode
FROM <event-data-store-id>
WHERE userIdentity.sessionContext.sessionIssuer.arn IN ({lst})
  AND eventName IN ({harvest})
  AND eventTime >= '{since_sql}'
ORDER BY eventTime;

-- 3) Athena over the CloudTrail S3 table (replace <cloudtrail_table>)
SELECT eventtime, recipientaccountid, useridentity.accountid AS caller_account, useridentity.arn AS caller_arn,
       sourceipaddress, json_extract_scalar(requestparameters, '$.roleArn') AS role_arn, errorcode
FROM <cloudtrail_table>
WHERE eventname = 'AssumeRole'
  AND json_extract_scalar(requestparameters, '$.roleArn') IN ({lst})
  AND eventtime >= '{since_sql}'
ORDER BY eventtime;
"""
