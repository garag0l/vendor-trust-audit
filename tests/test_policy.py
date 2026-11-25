from __future__ import annotations

import random

from vendor_trust_audit.policy import is_broad, reach, resource_matches

A = "secretsmanager:GetSecretValue"
S = "arn:aws:secretsmanager:us-east-1:111122223333:secret:"


def P(*stmts):
    return [("p", s) for s in stmts]


def allow(action=A, resource="*", **kw):
    return {"Effect": "Allow", "Action": action, "Resource": resource, **kw}


def test_basic_allow_and_wildcard_actions():
    assert reach(P(allow()), None, A).broad
    assert reach(P(allow("secretsmanager:Get*")), None, A).allowed
    assert reach(P(allow("SecretsManager:getsecretvalue")), None, A).allowed  # actions are case-insensitive
    assert not reach(P(allow("secretsmanager:List*")), None, A).allowed


def test_not_action_and_not_resource():
    assert reach(P({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}), None, A).broad
    assert not reach(P({"Effect": "Allow", "NotAction": "secretsmanager:*", "Resource": "*"}), None, A).allowed
    r = reach(P({"Effect": "Allow", "Action": A, "NotResource": S + "prod/*"}), None, A)
    assert r.allowed  # everything except prod: still broad enough to count


def test_unconditional_deny_wins_conditional_deny_does_not():
    assert not reach(P(allow(), {"Effect": "Deny", "Action": "secretsmanager:*", "Resource": "*"}), None, A).allowed
    r = reach(
        P(
            allow(),
            {"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}}},
        ),
        None,
        A,
    )
    assert r.allowed


def test_conditional_allow_is_marked():
    r = reach(P(allow(Condition={"StringEquals": {"aws:ResourceTag/env": "dev"}})), None, A)
    assert r.allowed and r.conditional


def test_boundary_intersection():
    ident = P(allow())
    assert not reach(ident, P(allow("s3:*")), A).allowed
    r = reach(ident, P(allow(resource=S + "dev/*")), A)
    assert r.resources == (S + "dev/*",) and not r.broad
    r = reach(P(allow(resource=S + "dev/*")), P(allow()), A)
    assert r.resources == (S + "dev/*",)


def test_is_broad():
    assert is_broad("*")
    assert is_broad("arn:aws:secretsmanager:*:*:secret:*")
    assert is_broad("arn:aws:ssm:us-east-1:111122223333:parameter/*")
    assert is_broad("arn:aws:s3:::*") and is_broad("arn:aws:s3:::*/*")
    assert not is_broad("arn:aws:s3:::bucket/*")
    assert not is_broad(S + "prod/*")


def test_randomized_no_false_negatives_on_nested_patterns():
    """For nested wildcard shapes (*, prefix/*, exact), any concrete ARN that the reference evaluator allows must be
    covered by a pattern `reach` reports. Reference: identity allows, boundary allows, no unconditional deny."""
    rng = random.Random(1234)
    names = ["prod/db", "prod/api", "dev/db", "dev/api", "shared/x"]
    pats = ["*", S + "*", S + "prod/*", S + "dev/*", *[S + n for n in names]]

    def ref(stmts, arn):
        hit = False
        for _, s in stmts:
            if any(resource_matches(p, arn) for p in s["Resource"]):
                if s["Effect"] == "Deny":
                    return False
                hit = True
        return hit

    for _ in range(400):
        ident = P(
            *[
                {"Effect": rng.choice(["Allow", "Allow", "Deny"]), "Action": A, "Resource": rng.sample(pats, rng.randint(1, 2))}
                for _ in range(rng.randint(1, 3))
            ]
        )
        bnd = None
        if rng.random() < 0.5:
            bnd = P(
                *[
                    {"Effect": "Allow", "Action": A, "Resource": rng.sample(pats, rng.randint(1, 2))}
                    for _ in range(rng.randint(1, 2))
                ]
            )
        r = reach(ident, bnd, A)
        for n in names:
            arn = S + n
            expected = ref(ident, arn) and (bnd is None or ref(bnd, arn))
            got = any(resource_matches(p, arn) for p in r.resources)
            if expected:
                assert got, (ident, bnd, arn, r)
