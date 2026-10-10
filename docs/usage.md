# Usage

[← back to index](index.md)

## Commands

```bash
openshield check <package>              # analyse only, install nothing
openshield intercept -- npm install …   # analyse, then ask
openshield config                       # show effective settings
```

`check` is read-only and never prompts. `intercept` is the full loop.

---

## What you see

```
npm:request@2.88.2
[!!] 10/100 -- critical: serious problems found

  !  the maintainer has asked you to stop using this package
       the maintainer says: "request has been deprecated, see .../issues/3142"
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

sources
  osv            fetched 2026-10-10T07:30:00Z   live
  npm-registry   fetched 2026-10-10T07:30:00Z   live
  github         fetched 2026-10-10T07:30:00Z   cached
```

Every number traces to a row. The rows always add up to the score.

Lines marked `!` are **statements somebody made** — the maintainer deprecating
the package, or GitHub disabling the repo — not guesses from activity. They're
shown first because they change how everything below them reads.

---

## Bands

| Band | Means |
| --- | --- |
| `critical` | serious problems found |
| `high` | problems found |
| `medium` | some concerns |
| `low` | **nothing known against this** — not "safe" |

If a source fails you're told which, and the score is capped at 69 — so
incomplete evidence can never look clean.

---

## Exit codes

| | Meaning |
| --- | --- |
| `0` | ran — npm's own exit code is passed through |
| `10` | you said no |
| `11` | blocked by a remembered rejection *(M2)* |
| `12` | refused by policy — offline, no TTY, or unresolvable |
| `14` | reserved for the edit action *(M3)* |
| `20` | OpenShield itself broke |

On approve, OpenShield exits with **npm's** code, so `&&` chains behave.

---

## Config

`~/.openshield/config.toml` · precedence: **env > file > default**

| Key | Default | |
| --- | --- | --- |
| `offline_policy` | `fail-closed` | refuse if every source fails |
| `noninteractive_policy` | `deny` | no TTY → don't install |
| `unresolvable_policy` | `prompt` | can't pin a version → ask anyway |
| `cache_ttl_hours` | `24` | |

Fail-closed is the default because the alternative installs unreviewed code,
and the cost of the default is typing `npm install` yourself.

### GitHub token

Optional. Raises the rate limit from 60/hr to 5000/hr.

```bash
export OPENSHIELD_GITHUB_TOKEN=ghp_...
```

Environment only, never written to config. Without it the GitHub collector is
**skipped quietly** rather than reported as a failure — a warning that fires on
every single run is furniture, and you'd learn to skim past the real ones.