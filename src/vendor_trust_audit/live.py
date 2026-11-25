"""Live collection with boto3 (read-only: iam:GetAccountAuthorizationDetails)."""

from __future__ import annotations

from .gaad import Role, load_gaad

KEYS = ("UserDetailList", "GroupDetailList", "RoleDetailList", "Policies")


def fetch_gaad(session) -> dict:
    iam = session.client("iam")
    merged: dict[str, list] = {k: [] for k in KEYS}
    for page in iam.get_paginator("get_account_authorization_details").paginate(
        Filter=["Role", "LocalManagedPolicy", "AWSManagedPolicy"]
    ):
        for k in KEYS:
            merged[k] += page.get(k, [])
    return merged


def from_live(session, label: str = "live") -> list[Role]:
    return load_gaad(fetch_gaad(session), source=label)
