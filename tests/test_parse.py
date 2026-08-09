from openshield.parse import split_specifier
from openshield.parse import classify_specifier

def test_split_plain_package():
	assert split_specifier("axios") == ("axios", None)

def test_split_version_package():
	assert split_specifier("axios@1.7.2") == ("axios", "1.7.2")

def test_split_scoped_package():
	assert split_specifier("@babel/core") == ("@babel/core", None)

def test_split_versioned_scoped_package(): 
	assert split_specifier("@babel/core@7.24.0") == ("@babel/core", "7.24.0")


def test_classify_local_path():
    assert classify_specifier("./root") == "local_path"
    assert classify_specifier("/openshield") == "local_path"
    assert classify_specifier("./") == "local_path"
    assert classify_specifier("../") == "local_path"
    assert classify_specifier("../x") == "local_path"


def test_classify_vcs():
    assert classify_specifier(
        "git+https://github.com/user/repo.git"
    ) == "vcs"
    assert classify_specifier("github:user/repo") == "vcs"


def test_classify_tarball():
    assert classify_specifier(
        "https://example.com/package.tgz"
    ) == "tarball"


def test_classify_registry_and_range():
    assert classify_specifier("axios") == "registry"
    assert classify_specifier("axios@1.7.2") == "registry"
    assert classify_specifier("axios@^1.0.0") == "range"
    assert classify_specifier("axios@~1.2") == "range"
    assert classify_specifier("axios@1.x") == "range"
    assert classify_specifier("axios@1.X") == "range"
    assert classify_specifier("axios@latest") == "range"
    assert classify_specifier("axios@next") == "range"