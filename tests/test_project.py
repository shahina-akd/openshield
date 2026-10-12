from pathlib import Path

import pytest

from openshield.project import current_path, current_project, find_root, project_id


def make(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text("{}")
    return root


def test_find_root_walks_up_from_a_subdirectory(tmp_path):
    app = make(tmp_path / "app")
    (app / "src" / "deep").mkdir(parents=True)
    assert find_root(app / "src" / "deep") == app.resolve()


def test_find_root_returns_none_outside_any_project(tmp_path):
    assert find_root(tmp_path) is None


def test_current_path_uses_the_override(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENSHIELD_PROJECT", str(tmp_path))
    assert current_path() == tmp_path


def test_current_path_falls_back_to_the_working_directory(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENSHIELD_PROJECT", raising=False)
    monkeypatch.chdir(tmp_path)
    assert current_path().resolve() == tmp_path.resolve()


@pytest.mark.parametrize("a,b", [
    ("Dev/app", "dev/APP"),              # macOS is case-insensitive
    ("café", "café"),         # NFC vs NFD
    ("CAFÉ", "café"),         # both at once
])
def test_one_directory_is_one_project(tmp_path, a, b):
    make(tmp_path / a)
    assert project_id(tmp_path / a) == project_id(tmp_path / b)


def test_different_directories_stay_different(tmp_path):
    """The guard on the guard: normalising carelessly could map everything
    to one id, and every test above would still pass."""
    make(tmp_path / "app")
    make(tmp_path / "app2")
    assert project_id(tmp_path / "app") != project_id(tmp_path / "app2")


def test_a_symlinked_project_is_the_same_project(tmp_path):
    app = make(tmp_path / "app")
    link = tmp_path / "shortcut"
    link.symlink_to(app)
    assert project_id(link) == project_id(app)


def test_current_project_is_an_id_not_a_path(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENSHIELD_PROJECT", str(tmp_path))
    assert current_project() == project_id(tmp_path)
    assert str(tmp_path) not in current_project()