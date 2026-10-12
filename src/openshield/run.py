"""The intercept pipeline: run_intercept(argv) -> exit code."""
from __future__ import annotations

import os
import sys

from .collect import collect
from .decide import is_interactive, prompt
from .exit_codes import (
    INTERNAL_ERROR, POLICY_BLOCKED, PRIOR_REJECTION, REJECTED,
)
from .execute import run_npm
from .models import PackageRef, Unresolvable
from .parse import classify_invocation
from .render import (
    render_assessment, render_blocked, render_remembered, render_unresolvable,
)
from .resolve import resolve_all
from .score import score
from . import config
from .decisions import audit, get_decision, save_decision
from .project import current_project


def run_intercept(argv: list[str]) -> int:
    try:
        return _intercept(argv)
    except Exception as exc:
        # If OpenShield itself fails, install nothing.
        print(f"[!!] openshield failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return INTERNAL_ERROR


def _intercept(argv: list[str]) -> int:
    inv = classify_invocation(argv)

    if os.environ.get("OPENSHIELD_BYPASS") == "1":
        audit("bypass", detail=" ".join(inv.npm_args))
        return run_npm(inv.npm_args)

    # Non-install commands pass through before any network call.
    if inv.kind == "pass_through":
        if inv.lockfile_install:
            print("[--] lockfile install -- not reviewed")
        elif inv.bare_install:
            print("[--] bare install -- installs the lockfile, not reviewed")
        return run_npm(inv.npm_args)

    results = resolve_all(inv.specifiers)
    refs = [r for r in results if isinstance(r, PackageRef)]

    # Stored decisions are checked after resolve (the key needs an exact
    # version) and before collect, so a remembered decision makes no
    # collector calls.
    project = current_project()
    ttl_days = config.get("decision_ttl_days")
    decisions = {ref: get_decision(ref, project, ttl_days=ttl_days) for ref in refs}

    blocked = [ref for ref, d in decisions.items()
               if d is not None and d.action == "reject"]
    if blocked:
        # Explained from the stored score, without any network calls.
        for ref in blocked:
            print(render_blocked(ref, decisions[ref]))
        audit("policy_block", detail=f"prior rejection: "
                                     f"{', '.join(r.canonical for r in blocked)}")
        return PRIOR_REJECTION

    approved = [ref for ref, d in decisions.items()
                if d is not None and d.action == "approve"]
    if refs and len(approved) == len(refs) and not _has_unresolvable(results):
        # Every package is already approved within the TTL. Say that it was
        # not re-checked, since new advisories would not be seen.
        for ref in approved:
            print(render_remembered(ref, decisions[ref]))
        return run_npm(inv.npm_args)

    evidence = collect(refs)
    by_ref = {e.package: e for e in evidence}
    assessments = {r: score(by_ref[r]) for r in refs}

    # Print the analysis before any policy decision so a refusal always
    # comes with its reasons.
    blocks = [
        render_unresolvable(r) if isinstance(r, Unresolvable)
        else render_assessment(assessments[r])
        for r in results
    ]
    print("\n\n".join(blocks))

    # Offline checks come before the TTY check: "could not analyze" is the
    # more useful message.
    unreachable = [
        r for r in results
        if isinstance(r, Unresolvable) and r.reason == "network"
    ]
    if unreachable and not refs:
        if config.get("offline_policy") == "fail-open":
            print("\n[!!] nothing could be resolved -- proceeding anyway "
                  "(offline_policy: fail-open)")
        else:
            print("\n[!!] nothing could be resolved -- refusing "
                  "(offline_policy: fail-closed)")
            audit("policy_block", detail="offline: nothing resolved")
            return POLICY_BLOCKED

    if refs and all(not e.sources for e in evidence):
        if config.get("offline_policy") != "fail-open":
            print("\n[!!] every evidence source failed -- refusing "
                  "(offline_policy: fail-closed)")
            audit("policy_block", detail="offline: every source failed")
            return POLICY_BLOCKED

    if not is_interactive():
        if config.get("noninteractive_policy") != "allow":
            print("\n[!!] no TTY -- refusing (noninteractive_policy: deny)")
            audit("policy_block", detail="no TTY")
            return POLICY_BLOCKED

    if prompt() != "approve":
        _record_all(refs, project, "reject", assessments)
        return REJECTED

    _record_all(refs, project, "approve", assessments)

    # Run the original arguments, never a reconstructed command, so what runs
    # is exactly what was approved.
    return run_npm(inv.npm_args)


# ------------------------------- helpers --------------------------------------

def _has_unresolvable(results) -> bool:
    """Unresolvable specifiers must always be shown, even when every
    resolvable package is already approved."""
    return any(isinstance(r, Unresolvable) for r in results)


def _record_all(refs, project, action, assessments) -> None:
    """Store the decision for every package in the command.

    A rejection of a multi-package command is not stored: rejections never
    expire, and the user may have objected to only one of the packages.
    """
    if action == "reject" and len(refs) > 1:
        print("\n[--] rejected, but not remembered: a rejection is permanent "
              "and this command named several packages")
        audit("reject", detail=f"not persisted ({len(refs)} packages)")
        return

    for ref in refs:
        assessment = assessments.get(ref)
        save_decision(
            ref, project, action,
            trust_score=assessment.score if assessment else None,
            scoring_version=assessment.scoring_version if assessment else None,
        )