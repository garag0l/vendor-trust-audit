"""vendor-trust-audit command line."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from .checks import SEV, audit
from .gaad import from_file
from .report import all_findings, as_json, cloudtrail_queries, sarif, text
from .vendors import load_extra


def _accounts(values: list[str] | None) -> set[str]:
    out: set[str] = set()
    for v in values or []:
        p = Path(v)
        items = p.read_text(encoding="utf-8").split() if p.is_file() else v.split(",")
        out |= {i.strip().zfill(12) for i in items if i.strip()}
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="vendor-trust-audit",
        description="Find and rank AWS IAM roles that outside (vendor) accounts can assume: dormant trust, root principals, "
        "ExternalId-only trust, wildcard principals and roles that can read secrets.",
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "--gaad",
        metavar="FILE",
        action="append",
        help="`aws iam get-account-authorization-details` output (repeatable, one per account)",
    )
    src.add_argument("--live", action="store_true", help="read IAM with your AWS credentials (read-only)")
    p.add_argument("--profile", action="append", help="with --live: AWS profile (repeatable to cover several accounts)")
    p.add_argument(
        "--internal-accounts",
        action="append",
        metavar="IDS|FILE",
        help="comma-separated account ids (or a file) treated as yours, e.g. every account in the Org",
    )
    p.add_argument("--org-id", help="treat trust narrowed with aws:PrincipalOrgID == this id as internal")
    p.add_argument(
        "--vendor-map", metavar="FILE", help='JSON {"123456789012": "Vendor"} to name accounts missing from the built-in list'
    )
    p.add_argument("--dormant-days", type=int, default=90, help="role unused for this many days is dormant (default 90)")
    p.add_argument("--now", help="evaluate dormancy as of this ISO date (default: now); useful for reproducible reports")
    p.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text")
    p.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE instead of stdout")
    p.add_argument("--min-severity", choices=list(SEV), default="low", help="text output: hide findings below this (default low)")
    p.add_argument(
        "--cloudtrail-query",
        metavar="SINCE",
        help="print CloudTrail Lake / Athena queries for flagged roles since this date (e.g. 2026-09-01)",
    )
    p.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"], default="high")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    a = p.parse_args(argv)

    roles = []
    if a.gaad:
        for g in a.gaad:
            roles += from_file(g)
    else:
        try:
            import boto3
        except ImportError:
            print("live mode needs boto3: pip install 'vendor-trust-audit[live]'", file=sys.stderr)
            return 2
        from .live import from_live

        for prof in a.profile or [None]:
            roles += from_live(boto3.session.Session(profile_name=prof), label=f"live:{prof or 'default'}")

    now = None
    if a.now:
        now = datetime.fromisoformat(a.now)
        now = now if now.tzinfo else now.replace(tzinfo=UTC)
    reports = audit(
        roles,
        now=now,
        dormant_days=a.dormant_days,
        internal_accounts=_accounts(a.internal_accounts),
        org_id=a.org_id,
        vendor_map=load_extra(a.vendor_map) if a.vendor_map else None,
    )

    if a.cloudtrail_query:
        out = cloudtrail_queries(reports, a.cloudtrail_query)
    elif a.format == "json":
        out = json.dumps(as_json(reports), indent=2, default=str)
    elif a.format == "sarif":
        out = json.dumps(sarif(reports), indent=2)
    else:
        color = not a.no_color and not a.output and sys.stdout.isatty() and "NO_COLOR" not in os.environ
        out = text(reports, color=color, min_severity=a.min_severity)
    if a.output:
        Path(a.output).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)
    threshold = {"none": 99, **SEV}[a.fail_on]
    return 1 if any(SEV[f.severity] >= threshold for f in all_findings(reports)) else 0


if __name__ == "__main__":
    raise SystemExit(main())
