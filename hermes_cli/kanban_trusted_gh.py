"""Operator GitHub authority must not resolve executables through caller PATH."""
from pathlib import Path
import stat


def trusted_gh() -> str:
    path = Path("/usr/bin/gh")
    try:
        info = path.stat()
    except OSError as exc:
        raise OSError("trusted GitHub CLI is unavailable") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise OSError("trusted GitHub CLI ownership is unsafe")
    return str(path)
