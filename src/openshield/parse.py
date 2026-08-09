def split_specifier(spec: str) -> tuple[str, str | None]:
    """'axios@1.7.2' -> ('axios', '1.7.2');  '@babel/core' -> ('@babel/core', None)"""
    if spec.startswith("@"):
        at = spec.find("@", 1)          # a version delimiter would be a LATER '@'
        if at == -1:
            return spec, None
        return spec[:at], spec[at + 1:]
    name, sep, version = spec.partition("@")
    return (name, version) if sep else (name, None)

def classify_specifier(spec: str) -> str:
    if spec.startswith(("./", "../", "/")):
        return "local_path"
    
    if spec.startswith(("git+https://", "github:")):
        return "vcs"
    
    if spec.startswith("https://") and (
        spec.endswith(".tgz")
    ):
        return "tarball"

    _, version = split_specifier(spec)

    if version is not None:
        if version.startswith(("^", "~", "*", ">=", "<")):
            return "range"
        if version.endswith(("x", "X")):
            return "range"
        if version in ("latest", "next"):
            return "range"

    return "registry"

    