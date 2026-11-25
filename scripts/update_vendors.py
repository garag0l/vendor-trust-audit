"""Regenerate src/vendor_trust_audit/data/known_aws_accounts.json from fwdcloudsec/known_aws_accounts.

Usage: python scripts/update_vendors.py [--yaml accounts.yaml] [--commit SHA]
Needs PyYAML (dev-time only; the package itself has no dependencies).
The upstream data is Apache-2.0 licensed: https://github.com/fwdcloudsec/known_aws_accounts
"""

from __future__ import annotations

import argparse
import json
import subprocess
import urllib.request
from datetime import date
from pathlib import Path

import yaml

REPO = "https://github.com/fwdcloudsec/known_aws_accounts"
OUT = Path(__file__).resolve().parent.parent / "src" / "vendor_trust_audit" / "data" / "known_aws_accounts.json"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--yaml", help="local accounts.yaml (default: download at --commit)")
    ap.add_argument("--commit", help="upstream commit to pin (default: current HEAD)")
    a = ap.parse_args()
    commit = a.commit or subprocess.check_output(["git", "ls-remote", REPO, "HEAD"], text=True).split()[0]
    if a.yaml:
        text = Path(a.yaml).read_text(encoding="utf-8")
    else:
        url = f"https://raw.githubusercontent.com/fwdcloudsec/known_aws_accounts/{commit}/accounts.yaml"
        with urllib.request.urlopen(url, timeout=30) as r:  # noqa: S310 - fixed https URL
            text = r.read().decode("utf-8")
    accounts: dict[str, dict] = {}
    for entry in yaml.safe_load(text):
        for acct in entry.get("accounts") or []:
            acct = str(acct).zfill(12)
            accounts.setdefault(
                acct,
                {"name": str(entry["name"]), "type": entry.get("type", ""), "source": (entry.get("source") or [""])[0]},
            )
    doc = {
        "upstream": REPO,
        "commit": commit,
        "license": "Apache-2.0",
        "generated": date.today().isoformat(),
        "accounts": dict(sorted(accounts.items())),
    }
    OUT.write_text(json.dumps(doc, indent=1, sort_keys=False) + "\n", encoding="utf-8")
    print(f"wrote {len(accounts)} accounts from {commit[:12]} -> {OUT}")


if __name__ == "__main__":
    main()
