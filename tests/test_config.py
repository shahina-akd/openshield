"""config.py -- precedence, validation, and the secret rule.

The `isolated_config` fixture in conftest.py points OPENSHIELD_CONFIG at a
fresh tmp_path for every test, so nothing here reads your real
~/.openshield/config.toml. Same rule the cache follows, for the same reason.
"""
import pytest

from openshield import config

ALL_POLICY_KEYS = ["offline_policy", "noninteractive_policy",
                   "unresolvable_policy", "approval_scope"]


def write(text: str) -> None:
    config.config_path().parent.mkdir(parents=True, exist_ok=True)
    config.config_path().write_text(text)


# ------------------------------------------------------------------------------
# 1. This step changes no behaviour
# ------------------------------------------------------------------------------

@pytest.mark.parametrize("key,expected", [
    ("offline_policy", "fail-closed"),
    ("noninteractive_policy", "deny"),
    ("unresolvable_policy", "prompt"),
    ("cache_ttl_hours", 24),
    ("decision_ttl_days", 90),
    ("approval_scope", "project"),
])
def test_the_defaults_are_what_m0_hard_coded(key, expected):
    """Step 1.6's whole contract: every default equals the value the code
    already used. If one of these is wrong, the step changed behaviour -- which
    it is specifically not supposed to do."""
    assert config.get(key) == expected


def test_no_config_file_means_defaults_not_an_error():
    """The common case for a new user. A missing file is not a problem."""
    assert not config.config_path().exists()
    assert config.get("offline_policy") == "fail-closed"


def test_the_defaults_are_the_fail_closed_ones():
    """§11.1's posture, asserted rather than assumed. The cost of refusing is
    'type npm install yourself'; the cost of allowing is 'install unreviewed
    code'. These are not close."""
    assert config.get("offline_policy") == "fail-closed"
    assert config.get("noninteractive_policy") == "deny"


# ------------------------------------------------------------------------------
# 2. Precedence: env > file > default
# ------------------------------------------------------------------------------

def test_the_file_overrides_the_default():
    write('offline_policy = "fail-open"\n')
    assert config.get("offline_policy") == "fail-open"


def test_the_environment_overrides_the_file(monkeypatch):
    write('offline_policy = "fail-open"\n')
    monkeypatch.setenv("OPENSHIELD_OFFLINE_POLICY", "fail-closed")
    assert config.get("offline_policy") == "fail-closed"


def test_the_environment_overrides_the_default(monkeypatch):
    monkeypatch.setenv("OPENSHIELD_CACHE_TTL_HOURS", "1")
    assert config.get("cache_ttl_hours") == 1


def test_an_unset_key_in_a_present_file_still_uses_its_default():
    """A partial config file is the normal case -- nobody sets all six."""
    write('cache_ttl_hours = 48\n')
    assert config.get("cache_ttl_hours") == 48
    assert config.get("offline_policy") == "fail-closed"


# ------------------------------------------------------------------------------
# 3. The config never breaks the tool
# ------------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "this is not toml",
    'offline_policy = ',
    "[[[",
    'offline_policy = "fail-open"\noffline_policy = "fail-closed"\n',  # duplicate
])
def test_a_malformed_file_falls_back_to_defaults(text):
    """Same rule the cache follows: a convenience layer that can break the
    tool is a liability. A bad file degrades to the DEFAULTS, which are the
    safe values -- so a typo cannot accidentally open the gate."""
    write(text)
    assert config.get("offline_policy") == "fail-closed"


def test_a_file_that_is_a_list_not_a_table_falls_back():
    write("[[entry]]\nname = 'x'\n")
    assert config.get("offline_policy") == "fail-closed"


def test_an_unreadable_file_falls_back(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENSHIELD_CONFIG", str(tmp_path / "does" / "not" / "exist.toml"))
    assert config.get("offline_policy") == "fail-closed"


@pytest.mark.parametrize("key", ALL_POLICY_KEYS)
def test_an_unrecognised_policy_value_falls_back_to_the_default(key):
    """A typo must never become a policy. Falling back to the default means
    falling back to fail-closed, so the failure direction is safe -- and
    `openshield config` shows `source: default`, which is where the typo
    becomes visible."""
    write(f'{key} = "defintely-not-a-policy"\n')
    assert config.get(key) == config.DEFAULTS[key]


@pytest.mark.parametrize("value", ["abc", "", "-1", "1.5.2", None, [], {}])
def test_a_bad_integer_falls_back(value):
    write(f"cache_ttl_hours = {value!r}\n" if value is not None else "cache_ttl_hours = 0\n")
    assert isinstance(config.get("cache_ttl_hours"), int)


def test_a_negative_ttl_falls_back():
    """A negative TTL would make every entry instantly stale -- a cache that
    silently does nothing, which is worse than no cache because it looks like
    one."""
    write("cache_ttl_hours = -5\n")
    assert config.get("cache_ttl_hours") == 24


def test_zero_ttl_is_allowed():
    """Zero is a MEASUREMENT, not a mistake: 'never serve from cache' is a
    legitimate thing to want while debugging a parser."""
    write("cache_ttl_hours = 0\n")
    assert config.get("cache_ttl_hours") == 0


def test_policy_values_are_read_case_insensitively():
    write('offline_policy = "FAIL-OPEN"\n')
    assert config.get("offline_policy") == "fail-open"


# ------------------------------------------------------------------------------
# 4. Secrets are environment-only -- §13
# ------------------------------------------------------------------------------

def test_the_token_is_not_a_config_key():
    """§13. A config file ends up in screenshots, bug reports and dotfile
    repositories. The token is read directly from the environment by
    collect/github.py and never passes through this module."""
    assert "github_token" not in config.DEFAULTS
    assert not any("token" in key for key in config.DEFAULTS)


def test_asking_for_a_secret_raises_rather_than_returning_None():
    """A None would read as 'not configured' and could be quietly papered
    over. Raising says the lookup itself is wrong."""
    with pytest.raises(KeyError, match="environment-only"):
        config.get("github_token")


def test_a_token_in_the_config_file_is_ignored_entirely(monkeypatch):
    """Someone WILL put it there. It must have no effect -- not a partial
    effect, and not a fallback."""
    write('github_token = "ghp_secret_value_here"\n'
          'offline_policy = "fail-open"\n')
    monkeypatch.delenv("OPENSHIELD_GITHUB_TOKEN", raising=False)

    # The rest of the file still works...
    assert config.get("offline_policy") == "fail-open"
    # ...and the token is unreachable.
    with pytest.raises(KeyError):
        config.get("github_token")


def test_no_secret_appears_in_the_effective_output(monkeypatch):
    """`openshield config` prints effective(). This is the cheap test that
    usually only gets added after a leak."""
    monkeypatch.setenv("OPENSHIELD_GITHUB_TOKEN", "ghp_" + "x" * 36)
    write('github_token = "ghp_also_here"\n')

    rendered = repr(config.effective())

    assert "ghp_" not in rendered
    assert "token" not in rendered.casefold()


# ------------------------------------------------------------------------------
# 5. Unknown keys, and effective()
# ------------------------------------------------------------------------------

def test_an_unknown_key_raises():
    """A typo in the CODE, not in the user's file. Returning None would let a
    misspelled lookup silently read nothing."""
    with pytest.raises(KeyError, match="unknown config key"):
        config.get("offline_polcy")


def test_an_unknown_key_in_the_file_is_ignored():
    """A typo in the USER's file. It cannot be honoured, and refusing to start
    over an unrecognised line would be hostile -- `openshield config` showing
    `source: default` for the key they meant is the signal."""
    write('offline_polcy = "fail-open"\n')
    assert config.get("offline_policy") == "fail-closed"


def test_effective_reports_where_each_value_came_from(monkeypatch):
    """The SOURCE is the useful half. 'I set offline_policy and it is still
    fail-closed' is answered by seeing `source: default` -- which means the
    file was not read, or the key was misspelled."""
    write('cache_ttl_hours = 48\n')
    monkeypatch.setenv("OPENSHIELD_OFFLINE_POLICY", "fail-open")

    result = config.effective()

    assert result["offline_policy"] == {"value": "fail-open", "source": "env"}
    assert result["cache_ttl_hours"] == {"value": 48, "source": "file"}
    assert result["approval_scope"] == {"value": "project", "source": "default"}


def test_effective_covers_every_key():
    assert set(config.effective()) == set(config.DEFAULTS)


# ------------------------------------------------------------------------------
# 6. The template
# ------------------------------------------------------------------------------

def test_ensure_file_writes_a_template_once():
    assert config.ensure_file() is True
    assert config.config_path().exists()
    assert config.ensure_file() is False, "a second call overwrote the file"


def test_ensure_file_never_overwrites_an_existing_config():
    write('offline_policy = "fail-open"\n')
    config.ensure_file()
    assert config.get("offline_policy") == "fail-open"


def test_the_written_template_parses_and_matches_the_defaults():
    """A template whose values disagree with DEFAULTS would make a brand-new
    config file change behaviour -- the one thing this step must not do."""
    config.ensure_file()
    for key, expected in config.DEFAULTS.items():
        assert config.get(key) == expected


def test_the_template_mentions_every_key():
    """A key documented nowhere is a key nobody will ever set."""
    config.ensure_file()
    text = config.config_path().read_text()
    for key in config.DEFAULTS:
        assert key in text, f"{key} is undocumented in the template"


def test_the_template_says_secrets_are_environment_only():
    config.ensure_file()
    text = config.config_path().read_text().casefold()
    assert "openshield_github_token" in text
    assert "environment" in text