from openshield.parse import split_specifier

def test_split_plain_package():
	assert split_specifier("axios") == ("axios", None)

def test_split_version_package():
	assert split_specifier("axios@1.7.2") == ("axios", "1.7.2")

def test_split_scoped_package():
	assert split_specifier("@babel/core") == ("@babel/core", None)

def test_split_versioned_scoped_package(): 
	assert split_specifier("@babel/core@7.24.0") == ("@babel/core", "7.24.0")
