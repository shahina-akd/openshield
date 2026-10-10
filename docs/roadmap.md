# Roadmap

[← back to index](index.md)

**M1 complete.** 804 tests.

| | | |
| --- | --- | --- |
| **M0** | pipeline end to end, `check` + `intercept`, OSV | done |
| **M1** | npm + GitHub evidence, async, caching, real weights, config | done |
| **M2** | `PATH` shim + decision memory — `enable` / `disable` / `doctor` | next |
| M3 | rich output, `--json`, **edit**: offer the fixed version and re-check it | |
| M4 | LLM explanation of the evidence — explains only, never scores | |
| later | PyPI, transitive deps, malware feeds, Linux/Windows | |

---

## Why M2 is one milestone and not two

Interception without decision memory re-prompts you for every package you
approved yesterday, in every project, forever.

That's the exact dynamic that gets security tooling switched off and never
switched back on. It isn't a smaller version of the product — it's an annoying
one. The two ship together or neither does.

---

## Three levels of "off"

Being designed into M2, because a tool you can't turn off is one you hesitate
to turn on.

| | Scope | Takes effect |
| --- | --- | --- |
| `OPENSHIELD_BYPASS=1 npm install …` | one command | **immediately** |
| `openshield disable` | durable, all shells | **next shell session** |
| uninstall | permanent | immediately |

A `PATH` shim can't be removed from a shell that already resolved it, so
`disable` cannot take effect in the shell you type it in. The tool has to say
so plainly — the moment you want an escape hatch is the moment it blocked you.

---

## M3's edit action

The most-wanted feature from actually living with the tool: it prints
*"fixed in 1.2.6"* and then makes you retype it.

One trap already known: pick the fixed version **above the installed one,
within the matching branch**, then confirm it's installable. One advisory names
lodash `4.18.0`, which was never published — a naive "take the first fixed
version" would offer an install that cannot succeed.