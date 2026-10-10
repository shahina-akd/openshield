# OpenShield

A pause between `npm install` and running someone else's code.

OpenShield resolves what you are about to install to exact versions, collects
public evidence about those versions, computes a reproducible risk score, shows
you both, and waits for a decision.

Then it runs the install, or runs nothing.

---

## Why not `npm audit`

`npm audit` runs *after* installation — which means after `postinstall` scripts
have already executed arbitrary code on your machine. It also reports raw
advisory data with no interpretation: fifteen moderate findings in transitive
dependencies you cannot act on, which is how people learn to ignore it.

OpenShield inverts both. It runs *before* anything executes, and it reports on
the handful of packages you actually typed, at the exact versions you are
actually getting.

---

## Install

Requires Python 3.11+ and macOS.

```bash
git clone https://github.com/<you>/openshield
cd openshield
uv sync
```

Optional, but recommended — without a GitHub token the repository collector is
skipped, because anonymous access allows only 60 requests an hour:

```bash
export OPENSHIELD_GITHUB_TOKEN=ghp_...   # add to ~/.zshrc
```

A token needs no scopes. It reads public repository metadata only.

---

## Usage

### Review a package without installing anything

```bash
uv run openshield check axios@1.7.2
```

`check` is read-only. It never runs npm.

### Review, then install if you approve

```bash
uv run openshield intercept -- npm install axios@1.7.2
```

A convenient alias:

```bash
alias ni='uv run --directory /path/to/openshield openshield intercept -- npm install'
ni axios@1.7.2
```

### Example output

```
npm:request@2.88.2
[!!] 10/100 -- critical: serious problems found

  !  the maintainer has asked you to stop using this package
       the maintainer says: "request has been deprecated, see
       https://github.com/request/request/issues/3142"
  !  the maintainer has archived this repository

     score
       starting point                          60
       deprecated by its maintainer           -25
       repository is archived                 -20
       this version published 1800 days ago   -15
       12,000,000 weekly downloads            +10
       a single npm maintainer account         -8
       300 repository contributors             +8
       total                                   10

     no known vulnerabilities
     (nothing known against this -- not the same as safe)

sources
  osv            fetched 2026-10-10T07:30:00Z   live
  npm-registry   fetched 2026-10-10T07:30:00Z   live
  github         fetched 2026-10-10T07:30:00Z   cached

install? [y/N]
```

---

## What it looks at

| Source | Evidence |
| --- | --- |
| [OSV](https://osv.dev) | known vulnerabilities, severity, published fixes |
| npm registry | publish dates, maintainer count, downloads, licence, deprecation notices |
| GitHub | archived, disabled, last push, contributors, stars |

Every number in the score table traces to a field from a named source. A score
with no visible evidence behind it is a bug.

Responses are cached in SQLite for 24 hours. Failures are never cached.

---

## Configuration

`~/.openshield/config.toml`, with environment variables taking precedence:

```toml
offline_policy        = "fail-closed"   # or "fail-open"
noninteractive_policy = "deny"          # or "allow"
unresolvable_policy   = "prompt"        # or "deny", "allow"
cache_ttl_hours       = 24
```

```bash
uv run openshield config          # show effective values and where each came from
```

The defaults are fail-closed. The cost of refusing is that you type
`npm install` yourself; the cost of allowing is that you install unreviewed
code.

Secrets are read from the environment only and are never written to the config
file.

---

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | approved and installed, or passed through |
| `10` | you rejected it |
| `12` | blocked by policy — could not analyze, and the policy says refuse |
| `20` | internal error |

---

## Limitations

These are true of the finished tool, not just of this version.

1. **Direct dependencies only.** A vulnerable or malicious *transitive*
   dependency will not be surfaced. You are reviewing what you typed, not what
   npm resolves beneath it.

2. **A clean result means "nothing known against this," not "this is safe."**
   Every vulnerability database is a record of what somebody already caught and
   published.

3. **Not a sandbox.** OpenShield is a speed bump you chose to install. Anything
   invoking npm by absolute path bypasses it entirely. It raises the cost of an
   accident, not the cost of an attack.

4. **Scores are a reading aid, not a verdict.** The number orders your
   attention. The evidence underneath it is the actual output.

5. **Lockfile installs are not reviewed.** Bare `npm install` and `npm ci`
   install everything in the lockfile and run its `postinstall` scripts.
   OpenShield reports that it is not looking, and passes through. This is the
   largest gap between what the tool claims and what it does.

---

## Status

Working: the full pipeline — resolve, collect, score, render, decide, execute —
via `check` and `intercept`.

Not yet built:

- **Decision memory and shell interception.** Today you invoke OpenShield
  explicitly. Ambient interception of `npm install` ships together with memory
  of what you already approved, because interception without memory re-prompts
  you forever and that is how security tooling gets disabled.
- **Offering the fix.** When an advisory names a fixed version, OpenShield
  prints it. It cannot yet install it for you.
- **npm ecosystems other than npm, and platforms other than macOS.**

---

## Development

```bash
uv run pytest             
uv run pytest -q --tb=no
```

The scoring function is pure — no network, no clock, no randomness — and a test
enforces that by parsing its imports. The same test covers the renderer, which
must not be able to reach anything that executes an install.

---

## Licence

MIT

## Acknowledgements

OpenShield began as a hackathon project built with Lana Croysdale. The current
implementation is a ground-up rewrite, but the idea and the original prototype
were ours together.