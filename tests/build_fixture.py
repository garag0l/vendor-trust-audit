"""Build tests/fixtures/account_gaad.json: a synthetic get-account-authorization-details export.

Every role reproduces a publicly documented trust shape. The Qubole roles follow the trust policy shape in
Wiz's write-up (vendor account root + sts:ExternalId, dormant, Secrets Manager read):
https://www.wiz.io/blog/qubole-cross-account-access-abused-in-the-wild
Account 805246085872 is Qubole's published account. 464622532012 is Datadog's documented integration account.
Run: python tests/build_fixture.py  (CI checks that the committed fixture is reproducible).
"""

from __future__ import annotations

import json
from pathlib import Path

ACCT = "111122223333"
QUBOLE = "805246085872"
DATADOG = "464622532012"
UNKNOWN = "999988887777"
SISTER = "222233334444"  # another account in the same Org


def trust(principal, condition=None, sid="Vendor"):
    st = {"Sid": sid, "Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}
    if condition:
        st["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [st]}


def inline(name, *statements):
    return {"PolicyName": name, "PolicyDocument": {"Version": "2012-10-17", "Statement": list(statements)}}


def allow(actions, resources="*", **extra):
    return {"Effect": "Allow", "Action": actions, "Resource": resources, **extra}


def role(name, trust_doc, *, last_used=None, inline_policies=(), managed=(), boundary=None, created="2023-01-10T09:00:00Z"):
    r = {
        "Path": "/",
        "RoleName": name,
        "RoleId": "AROA" + name.upper().replace("-", "")[:17].ljust(17, "X"),
        "Arn": f"arn:aws:iam::{ACCT}:role/{name}",
        "CreateDate": created,
        "AssumeRolePolicyDocument": trust_doc,
        "InstanceProfileList": [],
        "RolePolicyList": list(inline_policies),
        "AttachedManagedPolicies": [{"PolicyName": m.split("/")[-1], "PolicyArn": m} for m in managed],
        "Tags": [],
        "RoleLastUsed": {"LastUsedDate": last_used, "Region": "us-east-1"} if last_used else {},
    }
    if boundary:
        r["PermissionsBoundary"] = {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": boundary}
    return r


def managed_policy(name, *statements):
    arn = f"arn:aws:iam::{ACCT}:policy/{name}"
    return arn, {
        "PolicyName": name,
        "PolicyId": "ANPA" + name.upper()[:17].ljust(17, "X"),
        "Arn": arn,
        "Path": "/",
        "DefaultVersionId": "v1",
        "AttachmentCount": 1,
        "IsAttachable": True,
        "PolicyVersionList": [
            {"Document": {"Version": "2012-10-17", "Statement": list(statements)}, "VersionId": "v1", "IsDefaultVersion": True}
        ],
    }


QUBOLE_PERMS = inline(
    "qubole-cluster-access",
    allow(["s3:*"]),
    allow(["secretsmanager:GetSecretValue", "secretsmanager:ListSecrets"]),
    allow(["ssm:GetParameter*", "ssm:DescribeParameters"]),
    allow(["lambda:GetFunctionConfiguration", "lambda:ListFunctions"]),
    allow(["ec2:Describe*", "ec2:RunInstances", "ec2:TerminateInstances"]),
    allow("iam:PassRole", f"arn:aws:iam::{ACCT}:role/qubole-ec2-instance"),
)
EXT_QUBOLE = {"StringEquals": {"sts:ExternalId": "QBL-7f3c9a1e-acme"}}
SHARED_EXT = {"StringEquals": {"sts:ExternalId": "shared-ext-id-2024"}}


def build() -> dict:
    readall_arn, readall = managed_policy("VendorReadAll", allow(["secretsmanager:GetSecretValue", "kms:Decrypt"]))
    nosecrets_arn, nosecrets = managed_policy(
        "VendorBoundaryNoSecrets", allow(["cloudwatch:*", "logs:*", "ec2:Describe*", "secretsmanager:ListSecrets"])
    )
    roles = [
        # 1. Qubole breach shape: root principal + ExternalId only, dormant, reads secrets. Expect VTA-001(info),002,003,004,005.
        role(
            "qubole-integration",
            trust({"AWS": f"arn:aws:iam::{QUBOLE}:root"}, EXT_QUBOLE),
            last_used="2025-03-02T11:20:00Z",
            inline_policies=[QUBOLE_PERMS],
        ),
        # 2. Same, fixed the way Wiz recommends: aws:SourceIp added and recently used. VTA-004 must clear.
        role(
            "qubole-integration-sourceip",
            trust(
                {"AWS": f"arn:aws:iam::{QUBOLE}:root"},
                {"StringEquals": {"sts:ExternalId": "QBL-0b1d2e3f-acme"}, "IpAddress": {"aws:SourceIp": ["203.0.113.0/24"]}},
            ),
            last_used="2026-11-20T08:00:00Z",
            inline_policies=[QUBOLE_PERMS],
        ),
        # 3. Datadog: specific vendor role + ExternalId, recently used, read-only metrics. Expect VTA-001(info) + VTA-004 (ExternalId only, medium).
        role(
            "DatadogIntegrationRole",
            trust({"AWS": f"arn:aws:iam::{DATADOG}:role/DatadogAWSIntegrationRole"}, SHARED_EXT),
            last_used="2026-11-24T23:10:00Z",
            inline_policies=[inline("dd", allow(["cloudwatch:Get*", "cloudwatch:List*", "ec2:Describe*", "tag:GetResources"]))],
        ),
        # 4. Unknown account, no ExternalId, account-id principal form, reuses nothing. Boundary removes the secret read.
        role(
            "partner-reporting",
            trust({"AWS": UNKNOWN}),
            last_used="2026-11-01T10:00:00Z",
            managed=[readall_arn],
            boundary=nosecrets_arn,
        ),
        # 5. Unknown account role principal with PrincipalArn narrowing but sharing the ExternalId with Datadog's role.
        role(
            "legacy-etl-vendor",
            trust(
                {"AWS": f"arn:aws:iam::{UNKNOWN}:role/etl-runner"},
                {**SHARED_EXT, "ArnEquals": {"aws:PrincipalArn": f"arn:aws:iam::{UNKNOWN}:role/etl-runner"}},
            ),
            last_used="2026-11-23T10:00:00Z",
            inline_policies=[inline("etl", allow("s3:GetObject", "arn:aws:s3:::acme-etl-exports/*"))],
        ),
        # 6. Wildcard principal, no condition. Expect VTA-006 critical.
        role(
            "open-trust-test",
            trust("*"),
            last_used="2026-11-24T00:00:00Z",
            inline_policies=[inline("none", allow("sts:GetCallerIdentity"))],
        ),
        # 7. Wildcard principal restricted to an Org id. Internal when --org-id o-acme12345 is passed, VTA-006 high otherwise.
        role(
            "org-shared-readonly",
            trust({"AWS": "*"}, {"StringEquals": {"aws:PrincipalOrgID": "o-acme12345"}}),
            last_used="2026-11-24T00:00:00Z",
            inline_policies=[inline("ro", allow(["ec2:Describe*"]))],
        ),
        # 8. Explicit deny on secrets wins over the managed allow. Dormant -> VTA-002 medium, no VTA-005 for secrets.
        role(
            "vendor-backup",
            trust(
                {"AWS": f"arn:aws:iam::{DATADOG}:root"},
                {"StringEquals": {"sts:ExternalId": "bk-unique-1"}, "IpAddress": {"aws:SourceIp": "198.51.100.7/32"}},
            ),
            managed=[readall_arn],
            inline_policies=[
                inline("deny-secrets", {"Effect": "Deny", "Action": ["secretsmanager:*", "kms:Decrypt"], "Resource": "*"})
            ],
        ),
        # --- must produce nothing ---
        role(
            "internal-ci",
            trust({"AWS": f"arn:aws:iam::{ACCT}:role/github-actions"}),
            last_used="2026-11-24T00:00:00Z",
            inline_policies=[QUBOLE_PERMS],
        ),
        role("lambda-exec", trust({"Service": "lambda.amazonaws.com"}), inline_policies=[QUBOLE_PERMS]),
        role(
            "sister-account-deployer",
            trust({"AWS": f"arn:aws:iam::{SISTER}:role/deployer"}),
            last_used="2026-11-24T00:00:00Z",
            inline_policies=[QUBOLE_PERMS],
        ),
        role(
            "sso-admin",
            trust(
                {"Federated": f"arn:aws:iam::{ACCT}:saml-provider/AWSSSO"},
                {"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}},
            ),
        ),
    ]
    # managed policies are stored as JSON strings in some exports; exercise both forms
    readall["PolicyVersionList"][0]["Document"] = json.dumps(readall["PolicyVersionList"][0]["Document"])
    return {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": roles, "Policies": [readall, nosecrets]}


if __name__ == "__main__":
    out = Path(__file__).parent / "fixtures" / "account_gaad.json"
    out.write_text(json.dumps(build(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}")
