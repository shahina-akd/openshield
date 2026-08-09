def split_specifier(spec: str) -> tuple[str, str | None]:
    """'axios@1.7.2' -> ('axios', '1.7.2');  '@babel/core' -> ('@babel/core', None)"""
    if spec.startswith("@"):
        at = spec.find("@", 1)          # a version delimiter would be a LATER '@'
        if at == -1:
            return spec, None
        return spec[:at], spec[at + 1:]
    name, sep, version = spec.partition("@")
    return (name, version) if sep else (name, None)
