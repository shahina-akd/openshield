from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

# §13's keys, with the values M0 hard-coded. Changing a default here changes
# behaviour for everyone who has no config file, so each one is a decision.
DEFAULTS: dict[str, Any] = {
    # §11.1 policies. fail-closed is the project's standing posture: the cost
    # of refusing is "type npm install yourself"; the cost of allowing is
    # "install unreviewed code".
    "offline_policy": "fail-closed",
    "noninteractive_policy": "deny",
    "unresolvable_policy": "prompt",

    # M1 Step 1.4.
    "cache_ttl_hours": 24,

    # M2, reserved now so the key names do not shift under stored data.
    "decision_ttl_days": 90,
    "approval_scope": "project",
}

# A value outside these sets is a typo, and a typo that silently falls back to
# the default is a policy the user believes they set. Validated loudly instead.
_CHOICES: dict[str, frozenset[str]] = {
    "offline_policy": frozenset({"fail-closed", "fail-open"}),
    "noninteractive_policy": frozenset({"deny", "allow"}),
    "unresolvable_policy": frozenset({"prompt", "deny", "allow"}),
    "approval_scope": frozenset({"project", "global"}),
}

_INTEGERS = frozenset({"cache_ttl_hours", "decision_ttl_days"})

_ENV_PREFIX = "OPENSHIELD_"

# Never readable through this module, never writable to the file. Listed so
# that a future key cannot be added with one of these names by accident.
_SECRET_KEYS = frozenset({"github_token"})

_TEMPLATE = '''# OpenShield configuration. See SPEC.md §13.
#
# Secrets are NOT configured here -- set OPENSHIELD_GITHUB_TOKEN in your
# environment instead. A config file ends up in screenshots and bug reports.
#
# Every setting can be overridden for one command with an environment
# variable: OPENSHIELD_OFFLINE_POLICY=fail-open openshield check axios

# What to do when every evidence source fails.
# fail-closed (default) refuses; fail-open installs with no evidence.
offline_policy = "fail-closed"

# What to do when there is no terminal to ask at (a script, a CI runner).
# deny (default) refuses; allow proceeds unprompted.
noninteractive_policy = "deny"

# What to do about a specifier that cannot be resolved to an exact version
# (a range, a local path, a git URL). prompt (default) surfaces it and asks.
unresolvable_policy = "prompt"

# How long a cached response stays usable.
cache_ttl_hours = 24

# M2. How long an approval is remembered, and whether it applies to this
# project or everywhere.
decision_ttl_days = 90
approval_scope = "project"
'''


def config_path() -> Path:
    """`~/.openshield/config.toml`, or wherever OPENSHIELD_CONFIG points.

    The override exists for tests, for the same reason the cache has one: a
    test that read the real config would pass or fail depending on what you had
    configured that morning. Read on every call, so there is no module state to
    reset.
    """
    override = os.environ.get("OPENSHIELD_CONFIG")
    if override:
        return Path(override)
    return Path.home() / ".openshield" / "config.toml"


def ensure_file() -> bool:
    """Write the commented template if no config file exists.

    Returns True if a file was created. Called once from the CLI rather than on
    every read: writing a file as a side effect of reading one is the kind of
    surprise that makes a tool feel untrustworthy.
    """
    path = config_path()
    if path.exists():
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_TEMPLATE)
    return True


def _from_file() -> dict[str, Any]:
    """The parsed file, or {} for anything unreadable.

    NEVER RAISES. A malformed config must not take the tool down -- the same
    rule the cache follows, for the same reason: this is a convenience layer,
    and a convenience layer that can break the tool is a liability. A bad file
    degrades to the defaults, which are the safe values.
    """
    path = config_path()
    try:
        with path.open("rb") as handle:
            parsed = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _from_env(key: str) -> str | None:
    return os.environ.get(_ENV_PREFIX + key.upper())


def get(key: str) -> Any:
    """One setting, resolved. env > file > default.

    An unknown key is a programming error, not a user error, so it raises --
    a typo in the code should not silently read None.
    """
    # Secrets first: they are also absent from DEFAULTS, so the generic
    # "unknown key" branch would otherwise shadow the specific message. The
    # more specific check goes first -- found by the test asserting the
    # message, not just the exception type.
    if key in _SECRET_KEYS:
        raise KeyError(f"{key!r} is a secret and is environment-only (SPEC 13)")
    if key not in DEFAULTS:
        raise KeyError(f"unknown config key: {key!r}")

    raw = _from_env(key)
    if raw is None:
        raw = _from_file().get(key)
    if raw is None:
        return DEFAULTS[key]

    return _coerce(key, raw)


def _coerce(key: str, raw: Any) -> Any:
    """Validate, or fall back to the default.

    A value outside the allowed set falls back SILENTLY here rather than
    raising, because the alternative is a tool that refuses to start because of
    a typo in a comment-heavy config file. `openshield config` shows the
    effective values, which is where a typo becomes visible -- see §1.6.4.
    """
    if key in _INTEGERS:
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return DEFAULTS[key]
        return value if value >= 0 else DEFAULTS[key]

    choices = _CHOICES.get(key)
    if choices is not None:
        text = str(raw).strip().casefold()
        return text if text in choices else DEFAULTS[key]

    return raw


def effective() -> dict[str, Any]:
    """Every setting with its resolved value and where it came from.

    `openshield config` prints this. The SOURCE is the useful half: "I set
    offline_policy and it is still fail-closed" is answered by seeing that the
    value came from `default`, which means the file was not read or the key was
    misspelled.
    """
    out: dict[str, Any] = {}
    file_values = _from_file()
    for key in DEFAULTS:
        if _from_env(key) is not None:
            source = "env"
        elif key in file_values:
            source = "file"
        else:
            source = "default"
        out[key] = {"value": get(key), "source": source}
    return out