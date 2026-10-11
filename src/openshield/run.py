"""The intercept pipeline: run_intercept(argv) -> exit code."""
from __future__ import annotations

import os
import sys

from .collect import collect
from .decide import is_interactive, prompt
from .exit_codes import INTERNAL_ERROR, OK, POLICY_BLOCKED, REJECTED
from .execute import run_npm
from .models import PackageRef, Unresolvable
from .parse import classify_invocation
from .render import render_assessment, render_unresolvable
from .resolve import resolve_all
from .score import score
from . import config


def run_intercept(argv: list[str]) -> int:
    try:
        return _intercept(argv)
    except Exception as exc:
        # If OpenShield itself fails, install nothing.
        print(f"[!!] openshield failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return INTERNAL_ERROR


def _intercept(argv: list[str]) -> int:
    if os.environ.get("OPENSHIELD_BYPASS") == "1":
        return run_npm(classify_invocation(argv).npm_args)

    # Non-install commands pass through before any network call.
    inv = classify_invocation(argv)
    if inv.kind == "pass_through":
        if inv.lockfile_install:
            print("[--] lockfile install -- not reviewed")
        elif inv.bare_install:
            print("[--] bare install -- installs the lockfile, not reviewed")
        return run_npm(inv.npm_args)

    results = resolve_all(inv.specifiers)
    refs = [r for r in results if isinstance(r, PackageRef)]
    evidence = collect(refs)
    by_ref = {e.package: e for e in evidence}

    # Print the analysis before any policy decision so a refusal always
    # comes with its reasons.
    blocks = [
        render_unresolvable(r) if isinstance(r, Unresolvable)
        else render_assessment(score(by_ref[r]))
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
            return POLICY_BLOCKED

    if refs and all(not e.sources for e in evidence):
        if config.get("offline_policy") != "fail-open":
            print("\n[!!] every evidence source failed -- refusing "
                  "(offline_policy: fail-closed)")
            return POLICY_BLOCKED

    if not is_interactive():
        if config.get("noninteractive_policy") != "allow":
            print("\n[!!] no TTY -- refusing (noninteractive_policy: deny)")
            return POLICY_BLOCKED

    # One prompt for the whole command, not one per package.
    if prompt() != "approve":
        return REJECTED

    # Run the original arguments, never a reconstructed command, so what runs
    # is exactly what was approved.
    return run_npm(inv.npm_args)