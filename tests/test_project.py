
from openshield.project import current_project


def test_current_project_defaults_to_working_directory(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENSHIELD_PROJECT", raising=False)
    monkeypatch.chdir(tmp_path)

    assert current_project() == str(tmp_path.resolve())


def test_current_project_uses_override(monkeypatch, tmp_path):
    project = tmp_path / "my-project"
    monkeypatch.setenv("OPENSHIELD_PROJECT", str(project))

    assert current_project() == str(project.resolve())
