"""Live mode against moto's IAM: the GAAD paginator path produces the same roles as an export."""

from __future__ import annotations

import json

import boto3
import pytest
from moto import mock_aws

from vendor_trust_audit.checks import audit
from vendor_trust_audit.live import from_live


@pytest.fixture
def session(monkeypatch):
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    with mock_aws():
        yield boto3.session.Session(region_name="us-east-1")


def test_live_collection(session):
    iam = session.client("iam")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::805246085872:root"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": "qbl-test"}},
            }
        ],
    }
    iam.create_role(RoleName="qubole", AssumeRolePolicyDocument=json.dumps(trust))
    iam.put_role_policy(
        RoleName="qubole",
        PolicyName="read",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}],
            }
        ),
    )
    iam.create_role(
        RoleName="lambda",
        AssumeRolePolicyDocument=json.dumps(
            {"Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        ),
    )
    roles = from_live(session)
    assert {r.name for r in roles} >= {"qubole", "lambda"}
    (rep,) = audit(roles)
    assert rep.role.name == "qubole"
    assert {f.id for f in rep.findings} >= {"VTA-002", "VTA-003", "VTA-004", "VTA-005"}
