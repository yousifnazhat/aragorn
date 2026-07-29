"""Root-owned systemd entrypoint for the release-pinned coordinator."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from types import ModuleType

_IDENTITY = Path("/etc/aragorn/protected-broker-release.json")
_LAUNCHER = Path(
    "/usr/libexec/aragorn/aragorn-protected-install-launcher.py"
)
_MAX_IDENTITY_BYTES = 16 * 1024
_MAX_LAUNCHER_BYTES = 1024 * 1024


def _root_file(path: Path, maximum: int, *, expected_uid: int = 0) -> bytes:
    if path.resolve(strict=True) != path:
        raise ValueError("protected control path is not canonical")
    current = path.parent
    while True:
        metadata = os.lstat(current)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid not in {0, expected_uid}
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise ValueError("protected control ancestry is unsafe")
        if current == Path(current.anchor):
            break
        current = current.parent
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or before.st_nlink != 1
            or before.st_size > maximum
            or before.st_mode & (stat.S_ISUID | stat.S_ISGID)
            or stat.S_IMODE(before.st_mode) & 0o022
        ):
            raise ValueError("protected control file is unsafe")
        raw = os.read(descriptor, maximum + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_gid,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    if (
        len(raw) > maximum
        or len(raw) != after.st_size
        or identity
        != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
    ):
        raise ValueError("protected control file changed while read")
    return raw


def _verified_package_root() -> Path:
    raw = _root_file(_IDENTITY, _MAX_IDENTITY_BYTES)
    identity = json.loads(raw)
    launcher = identity["launcher"]
    expected_digest = launcher["digest"]
    launcher_raw = _root_file(_LAUNCHER, _MAX_LAUNCHER_BYTES)
    if (
        launcher["path"] != str(_LAUNCHER)
        or expected_digest
        != "sha256:" + hashlib.sha256(launcher_raw).hexdigest()
    ):
        raise ValueError("protected launcher identity changed")
    module = ModuleType("_aragorn_protected_install_launcher")
    module.__file__ = str(_LAUNCHER)
    exec(  # noqa: S102 - execute only stable, release-digest-pinned bytes
        compile(launcher_raw, str(_LAUNCHER), "exec"),
        module.__dict__,
    )
    module._validated_launch(
        _IDENTITY,
        (),
        expected_uid=0,
        launcher_path=_LAUNCHER,
    )
    verified = module._load_identity(_IDENTITY, 0)
    return Path(verified["package"]["root"])


def main() -> int:
    if sys.platform != "linux" or os.geteuid() != 0:
        print("aragorn coordinator: Linux root execution is required", file=sys.stderr)
        return 126
    try:
        root = _verified_package_root()
        source = root / "src"
        if (
            root.resolve(strict=True) != root
            or source.resolve(strict=True) != source
        ):
            raise ValueError("release package source root is unsafe")
        sys.path.insert(0, str(source))
        from aragorn.protected_install_coordinator import main as coordinate

        return coordinate()
    except (KeyError, OSError, TypeError, ValueError) as exc:
        print(f"aragorn coordinator: {exc}", file=sys.stderr)
        return 126


if __name__ == "__main__":
    raise SystemExit(main())
