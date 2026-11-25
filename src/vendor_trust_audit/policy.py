"""Minimal IAM identity-policy evaluator used to estimate what an assumable role can read.

Handles Allow/Deny, Action/NotAction, Resource/NotResource, `*`/`?` wildcards and permission boundaries.
Conditions on Allow statements are reported (the grant is marked conditional), not evaluated; conditional
Denies are not assumed to apply. SCPs and resource policies are out of scope (documented in the README).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache


def as_list(x) -> list:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


@lru_cache(maxsize=8192)
def _rx(pattern: str, case_insensitive: bool) -> re.Pattern:
    body = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    return re.compile(f"^{body}$", (re.I if case_insensitive else 0) | re.S)


def action_matches(pattern: str, action: str) -> bool:
    return bool(_rx(str(pattern), True).match(action))


def resource_matches(pattern: str, arn: str) -> bool:
    return bool(_rx(str(pattern), False).match(arn))


def _action_in(stmt: dict, action: str) -> bool:
    if "NotAction" in stmt:
        return not any(action_matches(p, action) for p in as_list(stmt["NotAction"]))
    return any(action_matches(p, action) for p in as_list(stmt.get("Action")))


def _resource_in(stmt: dict, arn: str) -> bool:
    if "NotResource" in stmt:
        return not any(resource_matches(p, arn) for p in as_list(stmt["NotResource"]))
    return any(resource_matches(p, arn) for p in as_list(stmt.get("Resource")))


@dataclass(frozen=True)
class Reach:
    """Resources (as patterns) on which an action is allowed after denies and the boundary."""

    action: str
    resources: tuple[str, ...] = ()
    conditional: bool = False
    sources: tuple[str, ...] = field(default=())

    @property
    def allowed(self) -> bool:
        return bool(self.resources)

    @property
    def broad(self) -> bool:
        """Allowed on every resource of its type (``*``, ``arn:aws:s3:::*``, ``...:secret:*``, ``...:parameter/*``)."""
        return any(is_broad(r) for r in self.resources)


_BROAD_SEGMENT = re.compile(r"^\*$|^[A-Za-z-]+[:/]\*$")


def is_broad(pattern: str) -> bool:
    if pattern == "*":
        return True
    parts = pattern.split(":", 5)
    if len(parts) != 6:
        return False
    if parts[2] == "s3":  # arn:aws:s3:::bucket/key - only all buckets counts as broad
        return parts[5] in ("*", "*/*")
    return bool(_BROAD_SEGMENT.match(parts[5]))


def _candidates(stmts: list[tuple[str, dict]], action: str) -> list[str]:
    out: list[str] = []
    for _, st in stmts:
        if st.get("Effect") != "Allow" or not _action_in(st, action):
            continue
        if "NotResource" in st:
            out.append("*")  # NotResource allows everything except the listed resources
        else:
            out += [str(r) for r in as_list(st.get("Resource"))]
    return out


def _allows(stmts: list[tuple[str, dict]], action: str, res: str) -> tuple[bool, bool, str]:
    """Is `res` (a resource pattern treated literally) allowed? Returns (allowed, conditional, source)."""
    best: tuple[bool, bool, str] = (False, False, "")
    for name, st in stmts:
        if not _action_in(st, action) or not _resource_in(st, res):
            continue
        if st.get("Effect") == "Deny":
            if not st.get("Condition"):
                return (False, False, name)
            continue
        if st.get("Effect") == "Allow":
            cond = bool(st.get("Condition"))
            if not best[0] or (best[1] and not cond):
                best = (True, cond, name)
    return best


def reach(identity: list[tuple[str, dict]], boundary: list[tuple[str, dict]] | None, action: str) -> Reach:
    """Which resource patterns can `action` be performed on?

    Candidate patterns come from the Allow statements of the identity policies and the boundary; each candidate
    is then checked (as a literal) against both. This is an approximation of intersecting wildcard sets, and it is
    exact for the common shapes (``*``, service-wide and prefix wildcards).
    """
    cands = _candidates(identity, action) + (_candidates(boundary, action) if boundary is not None else [])
    seen: dict[str, None] = {}
    resources, cond, sources = [], False, []
    for c in cands:
        if c in seen:
            continue
        seen[c] = None
        ok, c1, src = _allows(identity, action, c)
        if not ok:
            continue
        if boundary is not None:
            okb, c2, _ = _allows(boundary, action, c)
            if not okb:
                continue
            c1 = c1 or c2
        resources.append(c)
        cond = cond or c1
        sources.append(src)
    # drop patterns that are covered by a broader allowed pattern
    resources = [r for r in resources if not any(o != r and resource_matches(o, r) for o in resources)]
    return Reach(action, tuple(resources), cond, tuple(dict.fromkeys(sources)))
