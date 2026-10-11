from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

# Changing a default changes behaviour for every user without a config file.
DEFAULTS: dict[str, Any] = {
    # Policies default to the safe (refusing) option.
    "offline_policy": "fail-closed",
    "noninteractive_policy": "deny",
    "unresolvable_policy": "prompt",

    "cache_ttl_hours": 24,

    # Reserved for decision storage.
    "decision_ttl_days": 90,
    "approval_scope": "project",
}

_CHOICES: dict[str, frozenset[str]] = {
    "offline_policy": frozenset({"fail-closed", "fail-open"}),
    "noninteractive_policy": frozenset({"deny", "allow"}),
    "unresolvable_policy": frozenset({"prompt", "deny", "allow"}),
    "approval_scope": frozenset({"project", "global"}),
}

_INTEGERS = frozenset({"cache_ttl_hours", "decision_ttl_days"})

_ENV_PREFIX = "OPENSHIELD_"

# Secrets are environment-only and can never be read through this module.
_SECRET_KEYS = frozenset({"github_token"})

_TEMPLATE = '''# OpenShield configuration.
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

# How long an approval is remembered, and whether it applies to this
# project or everywhere.
decision_ttl_days = 90
approval_scope = "project"
'''


def config_path() -> Path:
    """`~/.openshield/config.toml`, or OPENSHIELD_CONFIG if set (used by tests)."""
    override = os.environ.get("OPENSHIELD_CONFIG")
    if override:
        return Path(override)
    return Path.home() / ".openshield" / "config.toml"


def ensure_file() -> bool:
    """Write the template if no config file exists. Returns True if created."""
    path = config_path()
    if path.exists():
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_TEMPLATE)
    return True


def _from_file() -> dict[str, Any]:
    """The parsed file, or {} if missing or unreadable. Never raises."""
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
    """Resolve one setting: environment, then file, then default.

    Raises KeyError for secrets and unknown keys.
    """
    # Checked before the unknown-key branch so secrets get the specific message.
    if key in _SECRET_KEYS:
        raise KeyError(f"{key!r} is a secret and is environment-only")
    if key not in DEFAULTS:
        raise KeyError(f"unknown config key: {key!r}")

    raw = _from_env(key)
    if raw is None:
        raw = _from_file().get(key)
    if raw is None:
        return DEFAULTS[key]

    return _coerce(key, raw)


def _coerce(key: str, raw: Any) -> Any:
    """Validate a value, falling back to the default if it is invalid.

    Invalid values show up as `source: default` in `openshield config`.
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
    """Every setting with its resolved value and source (env, file or default)."""
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