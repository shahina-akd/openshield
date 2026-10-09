"""run.py -- the pipeline. run_intercept(argv) -> int is THE SEAM."""
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


def run_intercept(argv: list[str]) -> int:
    try:
        return _intercept(argv)
    except Exception as exc:
        # OpenShield broke. Exit 20 and install NOTHING -- the failure mode of
        # the alternative is installing unreviewed code because the analyzer
        # crashed, which is the one outcome worse than being annoying.
        print(f"[!!] openshield failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return INTERNAL_ERROR


def _intercept(argv: list[str]) -> int:
    # 1. BYPASS FIRST. The M2 shim checks this before invoking Python at all;
    #    honouring it here too means `OPENSHIELD_BYPASS=1 openshield intercept`
    #    behaves the same by hand as under the shim. M2 logs it to audit.
    if os.environ.get("OPENSHIELD_BYPASS") == "1":
        # argv minus a leading "npm", which is exactly what parse.py already
        # computes and tests (test_npm_args_never_include_npm). Reusing it
        # beats a second implementation of the same string trick.
        return run_npm(classify_invocation(argv).npm_args)

    # 2. Parse. Pass-through exits here, before any network call.
    inv = classify_invocation(argv)
    if inv.kind == "pass_through":
        if inv.lockfile_install:
            print("[--] lockfile install -- not reviewed (SPEC 3.3.6)")
        elif inv.bare_install:
            print("[--] bare install -- installs the lockfile, not reviewed")
        return run_npm(inv.npm_args)

    # 3. Resolve, collect, score -- the 0.3-0.5 pipeline, unchanged.
    results = resolve_all(inv.specifiers)
    refs = [r for r in results if isinstance(r, PackageRef)]
    evidence = collect(refs)
    by_ref = {e.package: e for e in evidence}

    # 4. Render EVERYTHING before any policy decision, so a refusal is always
    #    accompanied by the reason for it. §11.1's non-interactive branch says
    #    "print analysis as text, exit 12" -- not "exit 12".
    blocks = [
        render_unresolvable(r) if isinstance(r, Unresolvable)
        else render_assessment(score(by_ref[r]))
        for r in results
    ]
    print("\n\n".join(blocks))


    # 5. Policy. Order matters: offline before TTY, because "I could not
    #    analyze this" is a better message than "I cannot ask you".

    # Network failures during resolution must fail closed.
    unreachable = [
        r for r in results
        if isinstance(r, Unresolvable) and r.reason == "network"
    ]
    if unreachable and not refs:
        print("\n[!!] nothing could be resolved -- refusing "
              "(offline_policy: fail-closed)")
        return POLICY_BLOCKED

    if refs and all(not e.sources for e in evidence):
        print("\n[!!] every evidence source failed -- refusing "
              "(offline_policy: fail-closed)")
        return POLICY_BLOCKED

    if not is_interactive():
        print("\n[!!] no TTY -- refusing (noninteractive_policy: deny)")
        return POLICY_BLOCKED

    # 6. The pause. ONE prompt for the whole command line (§11.1), not one per
    #    package: you are approving the command you typed. M2 records a
    #    decision per package ref from this single answer.
    if prompt() != "approve":
        return REJECTED

    # 7. The only reachable call to run_npm on the analysis path, and it runs
    #    the ORIGINAL argv -- never a reconstructed command. Anything rebuilt
    #    from parsed specifiers could differ from what the user typed, and the
    #    thing they approved is what they typed.
    return run_npm(inv.npm_args)