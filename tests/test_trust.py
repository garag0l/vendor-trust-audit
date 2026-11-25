from __future__ import annotations

from vendor_trust_audit.trust import external_grants

OWN = "111122223333"


def st(principal, cond=None, action="sts:AssumeRole", effect="Allow"):
    s = {"Effect": effect, "Principal": principal, "Action": action}
    if cond:
        s["Condition"] = cond
    return {"Statement": [s]}


def test_principal_forms():
    g = external_grants(
        st(
            {
                "AWS": [
                    "arn:aws:iam::805246085872:root",
                    "464622532012",
                    "arn:aws:iam::999988887777:role/a",
                    "arn:aws:sts::999988887777:assumed-role/a/s",
                ]
            }
        ),
        OWN,
    )
    assert [(x.account, x.kind) for x in g] == [
        ("805246085872", "root"),
        ("464622532012", "account"),
        ("999988887777", "role"),
        ("999988887777", "assumed-role"),
    ]


def test_service_federated_deny_and_other_actions_ignored():
    assert external_grants(st({"Service": "ec2.amazonaws.com"}), OWN) == []
    assert external_grants(st({"Federated": "cognito-identity.amazonaws.com"}, action="sts:AssumeRoleWithWebIdentity"), OWN) == []
    assert external_grants(st({"AWS": "805246085872"}, effect="Deny"), OWN) == []
    assert external_grants(st({"AWS": "805246085872"}, action="sts:TagSession"), OWN) == []
    assert len(external_grants(st({"AWS": "805246085872"}, action="sts:*"), OWN)) == 1
    assert len(external_grants(st({"AWS": "805246085872"}, action=["sts:AssumeRole", "sts:TagSession"]), OWN)) == 1


def test_not_action_trust():
    t = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "805246085872"}, "NotAction": "sts:TagSession"}]}
    assert len(external_grants(t, OWN)) == 1
    t["Statement"][0]["NotAction"] = "sts:*"
    assert external_grants(t, OWN) == []


def test_own_and_internal_accounts_excluded():
    assert external_grants(st({"AWS": f"arn:aws:iam::{OWN}:root"}), OWN) == []
    assert external_grants(st({"AWS": "arn:aws:iam::222233334444:root"}), OWN, {"222233334444"}) == []


def test_narrowing_ignores_ifexists_and_negated_operators():
    cond = {
        "StringEquals": {"sts:ExternalId": "x"},
        "IpAddressIfExists": {"aws:SourceIp": "203.0.113.0/24"},
        "StringNotEquals": {"aws:PrincipalOrgID": "o-other"},
    }
    (g,) = external_grants(st({"AWS": "805246085872"}, cond), OWN)
    assert g.external_ids == ["x"] and g.narrowing == {}


def test_narrowing_keys_recognised_case_insensitively():
    for cond in (
        {"IpAddress": {"aws:sourceip": "203.0.113.0/24"}},
        {"StringEquals": {"aws:SourceVpce": "vpce-1"}},
        {"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::805246085872:role/q*"}},
        {"StringEquals": {"aws:PrincipalTag/team": "data"}},
        {"StringLike": {"sts:SourceIdentity": "q-*"}},
    ):
        (g,) = external_grants(st({"AWS": "805246085872"}, cond), OWN)
        assert g.narrowing, cond


def test_negated_external_id_is_not_an_external_id():
    (g,) = external_grants(st({"AWS": "805246085872"}, {"StringNotEquals": {"sts:ExternalId": "x"}}), OWN)
    assert g.external_ids == [] and g.negated_external_id


def test_org_id_condition_makes_wildcard_internal():
    t = st({"AWS": "*"}, {"StringEquals": {"aws:PrincipalOrgID": "o-acme12345"}})
    assert external_grants(t, OWN, org_id="o-acme12345") == []
    assert len(external_grants(t, OWN, org_id="o-someone-else")) == 1
    assert external_grants(st("*"), OWN)[0].kind == "wildcard"
