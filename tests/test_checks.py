from __future__ import annotations

import pytest
from conftest import FIXTURE, NOW

from vendor_trust_audit.checks import audit
from vendor_trust_audit.gaad import from_file, load_gaad

ORG_ARGS = {"internal_accounts": {"222233334444"}, "org_id": "o-acme12345"}


@pytest.fixture(scope="module")
def reports():
    return {r.role.name: r for r in audit(from_file(FIXTURE), now=NOW, **ORG_ARGS)}


def ids(rep, sev=None):
    return sorted({f.id for f in rep.findings if sev is None or f.severity == sev})


def test_qubole_shape_hits_every_check(reports):
    r = reports["qubole-integration"]
    assert ids(r) == ["VTA-001", "VTA-002", "VTA-003", "VTA-004", "VTA-005"]
    assert r.vendors["805246085872"] == "qubole"
    assert r.dormant
    assert {"secretsmanager", "ssm-parameters", "lambda-env", "s3-read"} <= set(r.secret_classes)
    assert r.worst == "critical"
    sev = {f.id: f.severity for f in r.findings}
    assert sev["VTA-002"] == "high" and sev["VTA-004"] == "high" and sev["VTA-001"] == "info"


def test_source_ip_clears_external_id_only(reports):
    r = reports["qubole-integration-sourceip"]
    assert "VTA-004" not in ids(r)
    assert "VTA-002" not in ids(r)  # used 5 days ago
    assert "VTA-003" in ids(r) and "VTA-005" in ids(r)
    # secret reach with a narrowed, active trust is high, not critical
    assert next(f for f in r.findings if f.id == "VTA-005").severity == "high"


def test_datadog_known_vendor_external_id_only_and_reuse(reports):
    r = reports["DatadogIntegrationRole"]
    assert r.vendors["464622532012"] == "Datadog"
    titles = [f.title for f in r.findings if f.id == "VTA-004"]
    assert any("only thing" in t for t in titles)
    assert any("reused across different vendor accounts" in t for t in titles)
    assert "VTA-003" not in ids(r)  # names a specific vendor role
    assert "VTA-005" not in ids(r)


def test_principal_arn_narrowing_and_scoped_s3(reports):
    r = reports["legacy-etl-vendor"]
    assert [f for f in r.findings if f.id == "VTA-004" and "only thing" in f.title] == []
    assert "VTA-005" not in ids(r)  # s3:GetObject on one bucket is not broad read
    assert "s3-read" in {c for c, x in r.reach.items() if x.allowed}
    assert ids(r, "medium") == ["VTA-001", "VTA-004"]  # unknown account + ExternalId reuse


def test_boundary_removes_secret_reach(reports):
    r = reports["partner-reporting"]
    assert not r.reach["secretsmanager"].allowed
    assert not r.reach["kms-decrypt"].allowed
    assert "VTA-005" not in ids(r)
    # bare account id principal == root; no ExternalId -> high
    assert {"VTA-001", "VTA-003", "VTA-004"} <= set(ids(r))
    assert next(f for f in r.findings if f.id == "VTA-004").severity == "high"


def test_explicit_deny_wins(reports):
    r = reports["vendor-backup"]
    assert not r.reach["secretsmanager"].allowed and not r.reach["kms-decrypt"].allowed
    assert "VTA-005" not in ids(r)
    assert next(f for f in r.findings if f.id == "VTA-002").severity == "medium"
    assert "VTA-004" not in ids(r)  # SourceIp + ExternalId


def test_wildcard_principal_without_condition_is_critical(reports):
    r = reports["open-trust-test"]
    assert ids(r) == ["VTA-006"] and r.worst == "critical"


def test_no_false_positives_on_internal_service_federated_and_org(reports):
    for name in ("internal-ci", "lambda-exec", "sister-account-deployer", "sso-admin", "org-shared-readonly"):
        assert name not in reports


def test_without_org_context_sister_account_and_org_wildcard_are_reported():
    rs = {r.role.name: r for r in audit(from_file(FIXTURE), now=NOW)}
    assert "VTA-001" in ids(rs["sister-account-deployer"])
    assert ids(rs["org-shared-readonly"]) == ["VTA-006"]
    assert rs["org-shared-readonly"].worst == "high"


def test_dormant_days_threshold():
    rs = {r.role.name: r for r in audit(from_file(FIXTURE), now=NOW, dormant_days=3, **ORG_ARGS)}
    assert rs["qubole-integration-sourceip"].dormant  # 5 days old
    assert not rs["DatadogIntegrationRole"].dormant  # 1 day old


def test_vendor_map_names_unknown_account():
    rs = {r.role.name: r for r in audit(from_file(FIXTURE), now=NOW, vendor_map={"999988887777": "Acme ETL Co"}, **ORG_ARGS)}
    r = rs["partner-reporting"]
    assert r.vendors["999988887777"] == "Acme ETL Co"
    assert next(f for f in r.findings if f.id == "VTA-001").severity == "info"


def _one(trust, policies=(), last_used="2026-11-24T00:00:00Z"):
    return load_gaad(
        {
            "RoleDetailList": [
                {
                    "RoleName": "r",
                    "Arn": "arn:aws:iam::111122223333:role/r",
                    "AssumeRolePolicyDocument": trust,
                    "RolePolicyList": [{"PolicyName": "p", "PolicyDocument": {"Statement": list(policies)}}],
                    "AttachedManagedPolicies": [],
                    "RoleLastUsed": {"LastUsedDate": last_used},
                }
            ]
        }
    )


def test_not_action_policy_grants_secret_reach():
    trust = {
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::805246085872:role/x"}, "Action": "sts:AssumeRole"}]
    }
    (r,) = audit(_one(trust, [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]), now=NOW)
    assert "secretsmanager" in r.secret_classes and "VTA-005" in ids(r)


def test_unique_id_principal_from_deleted_vendor_role():
    trust = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "AROAEXAMPLEDELETED01"}, "Action": "sts:AssumeRole"}]}
    (r,) = audit(_one(trust), now=NOW)
    assert r.grants[0].kind == "unique-id"
    assert "VTA-001" in ids(r)


def test_single_role_external_id_not_flagged_as_reuse():
    trust = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::805246085872:role/x"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": "only-here"}},
            }
        ]
    }
    (r,) = audit(_one(trust), now=NOW)
    assert not any("reused" in f.title for f in r.findings)
