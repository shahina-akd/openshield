# OpenShield

A pause between `npm install` and running someone else's code.

Resolves what you're about to install to exact versions, collects public evidence
(OSV, npm registry, GitHub), scores it, shows you, and waits. Then it installs, or
it doesn't.

`npm audit` runs *after* installation — which is after `postinstall` scripts have
already executed. OpenShield runs before anything executes.

macOS, npm, direct dependencies only.

## Status

M0 in progress. Not usable yet.

## Limitations

These are permanent properties, not bugs:

1. **Direct dependencies only.** You're reviewing what you typed, not what npm
   resolves beneath it. A malicious transitive dependency will not be surfaced.
2. **A clean result means "nothing known against this,"** not "this is safe."
   Vulnerability databases record what somebody already caught and published.
3. **Lockfile installs pass through.** Bare `npm install` and `npm ci` install
   everything in the lockfile and run its postinstall scripts without review.
4. **Not a sandbox.** Anything invoking npm by absolute path bypasses the shim.
   This raises the cost of an accident, not of an attack.
5. **Scores are a reading aid, not a verdict.** The number orders your attention;
   the evidence underneath it is the actual output.
6. **Interception requires a new shell** after `openshield enable`.

## If it breaks your shell

    OPENSHIELD_BYPASS=1 npm install …   # escape hatch, checked before Python runs
    openshield disable                  # turn it off properly, then open a new shell
    openshield check <pkg>              # analysis without interception, always works

If the CLI itself is broken: delete everything between the `# >>> openshield >>>`
markers in `~/.zshrc` and open a new shell. A pre-modification backup is in
`~/.openshield/backups/`..
