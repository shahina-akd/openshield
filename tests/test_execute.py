"""execute.py -- the only module that runs npm."""
import os

from openshield import execute

def test_run_npm_never_uses_a_shell(monkeypatch, tmp_path):
    seen = {}

    def fake_run(cmd, *args, **kwargs):
        seen["cmd"] = cmd
        seen["kwargs"] = kwargs
        class R: returncode = 0
        return R()

    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setattr(execute, "real_npm", lambda path=None: "/usr/bin/npm")

    execute.run_npm(["install", "axios"])

    assert seen["cmd"] == ["/usr/bin/npm", "install", "axios"]   # a list
    assert seen["kwargs"].get("shell") is not True


def test_real_npm_keeps_node_manager_shims(tmp_path, monkeypatch):
    """Only OUR directory is removed. An nvm shim must still win, or npm runs
    under the wrong Node."""
    nvm = tmp_path / ".nvm" / "versions" / "node" / "v22" / "bin"
    nvm.mkdir(parents=True)
    (nvm / "npm").write_text("#!/bin/sh\nexit 0\n")
    (nvm / "npm").chmod(0o755)
    monkeypatch.setattr(execute, "SHIM_DIR", tmp_path / "shims")
    assert execute.real_npm(str(nvm)) == str(nvm / "npm")