"""Verify protected Aragorn code before import; host Python remains the TCB."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

_SCHEMA = "aragorn/protected-broker-launch-identity/v1"
_IDENTITY_PATH = Path("/etc/aragorn/protected-broker-release.json")
_MAX_IDENTITY_BYTES = 16 * 1024
_MAX_ENTRIES = 10_000
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_BYTES = 256 * 1024 * 1024
_CHUNK_BYTES = 1024 * 1024
_ENVIRONMENT = {
    "HOME": "/nonexistent",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "PYTHONDONTWRITEBYTECODE": "1",
    "TZ": "UTC",
}


class LaunchVerificationError(ValueError):
    """The protected release cannot be trusted for execution."""


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _require_digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise LaunchVerificationError(f"{label} is invalid")
    return value


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _require_absolute_real_path(value: object, label: str) -> Path:
    if not isinstance(value, str):
        raise LaunchVerificationError(f"{label} must be an absolute path")
    supplied = Path(value)
    try:
        resolved = supplied.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise LaunchVerificationError(f"cannot resolve {label}: {exc}") from exc
    if not supplied.is_absolute() or supplied != resolved:
        raise LaunchVerificationError(f"{label} must be an absolute real path")
    return resolved


def _require_protected_ancestors(path: Path, expected_uid: int) -> None:
    current = path.parent
    while True:
        try:
            metadata = os.lstat(current)
        except OSError as exc:
            raise LaunchVerificationError(
                f"cannot inspect protected ancestry: {exc}"
            ) from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid not in {0, expected_uid}
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise LaunchVerificationError(
                "protected ancestry is writable or has an unexpected owner"
            )
        if current == Path(current.anchor):
            return
        current = current.parent


def _reject_file_capabilities(path: Path) -> None:
    if sys.platform != "linux":
        return
    getxattr = getattr(os, "getxattr", None)
    if getxattr is None:
        raise LaunchVerificationError("cannot inspect Linux file capabilities")
    try:
        capabilities = getxattr(
            path,
            "security.capability",
            follow_symlinks=False,
        )
    except OSError as exc:
        absent = {
            errno.ENODATA,
            errno.ENOTSUP,
            getattr(errno, "ENOATTR", errno.ENODATA),
            getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
        }
        if exc.errno in absent:
            return
        raise LaunchVerificationError(
            f"cannot inspect Linux file capabilities: {exc}"
        ) from exc
    if capabilities:
        raise LaunchVerificationError("protected executable has file capabilities")


def _hash_regular_file(
    path: Path,
    *,
    expected_uid: int,
    max_bytes: int,
    executable: bool = False,
) -> tuple[str, os.stat_result]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise LaunchVerificationError(f"cannot open protected file: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or before.st_nlink != 1
            or before.st_mode & (stat.S_ISUID | stat.S_ISGID)
            or mode & 0o022
            or before.st_size > max_bytes
            or (executable and not mode & 0o111)
        ):
            raise LaunchVerificationError("protected file metadata is unsafe")
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(descriptor, _CHUNK_BYTES):
            size += len(chunk)
            if size > max_bytes:
                raise LaunchVerificationError("protected file exceeds its byte limit")
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if size != after.st_size or _identity(before) != _identity(after):
        raise LaunchVerificationError("protected file changed while reading")
    if executable:
        _reject_file_capabilities(path)
    return "sha256:" + digest.hexdigest(), after


def _load_identity(path: Path, expected_uid: int) -> dict[str, object]:
    _require_protected_ancestors(path, expected_uid)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or before.st_nlink != 1
            or before.st_mode & (stat.S_ISUID | stat.S_ISGID)
            or mode & 0o022
            or before.st_size > _MAX_IDENTITY_BYTES
        ):
            raise LaunchVerificationError("release identity metadata is unsafe")
        raw = os.read(descriptor, _MAX_IDENTITY_BYTES + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        len(raw) > _MAX_IDENTITY_BYTES
        or _identity(before) != _identity(after)
        or len(raw) != after.st_size
    ):
        raise LaunchVerificationError("release identity changed while reading")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise LaunchVerificationError(f"release identity is invalid: {exc}") from exc
    if not isinstance(document, dict) or _canonical_json(document) != raw:
        raise LaunchVerificationError("release identity must be canonical JSON")
    if set(document) != {"broker", "launcher", "package", "python", "schema"}:
        raise LaunchVerificationError("release identity has unexpected fields")
    if document["schema"] != _SCHEMA:
        raise LaunchVerificationError("release identity schema is unsupported")
    for name in ("broker", "launcher", "package", "python"):
        if not isinstance(document[name], dict):
            raise LaunchVerificationError(f"release identity {name} is invalid")
    return document


def _measure_package(root: Path, expected_uid: int) -> str:
    _require_protected_ancestors(root, expected_uid)
    pending = [root]
    files: list[tuple[str, Path, os.stat_result]] = []
    directories: list[tuple[Path, tuple[int, ...]]] = []
    entries = 0
    total_bytes = 0
    while pending:
        directory = pending.pop()
        try:
            before = os.lstat(directory)
            children = sorted(os.scandir(directory), key=lambda child: child.name)
        except OSError as exc:
            raise LaunchVerificationError(
                f"cannot inspect protected package: {exc}"
            ) from exc
        if (
            not stat.S_ISDIR(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_uid != expected_uid
            or before.st_mode & (stat.S_ISUID | stat.S_ISGID)
            or stat.S_IMODE(before.st_mode) & 0o022
        ):
            raise LaunchVerificationError("protected package directory is unsafe")
        if not children:
            raise LaunchVerificationError(
                "protected package contains an unpinned empty directory"
            )
        directories.append((directory, _identity(before)))
        child_directories: list[Path] = []
        for child in children:
            entries += 1
            if entries > _MAX_ENTRIES:
                raise LaunchVerificationError(
                    "protected package exceeds its entry limit"
                )
            path = Path(child.path)
            metadata = child.stat(follow_symlinks=False)
            if (
                stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != expected_uid
                or metadata.st_mode & (stat.S_ISUID | stat.S_ISGID)
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise LaunchVerificationError(
                    "protected package entry is unsafe"
                )
            if stat.S_ISDIR(metadata.st_mode):
                child_directories.append(path)
            elif stat.S_ISREG(metadata.st_mode):
                total_bytes += metadata.st_size
                if metadata.st_size > _MAX_FILE_BYTES:
                    raise LaunchVerificationError(
                        "protected package file exceeds 64 MiB"
                    )
                if total_bytes > _MAX_TOTAL_BYTES:
                    raise LaunchVerificationError(
                        "protected package exceeds 256 MiB"
                    )
                files.append((path.relative_to(root).as_posix(), path, metadata))
            else:
                raise LaunchVerificationError(
                    "protected package contains a special file"
                )
        after = os.lstat(directory)
        if _identity(before) != _identity(after):
            raise LaunchVerificationError(
                "protected package directory changed while enumerated"
            )
        pending.extend(reversed(child_directories))

    digest = hashlib.sha256()
    for relative, path, listed in sorted(files):
        file_digest, opened = _hash_regular_file(
            path,
            expected_uid=expected_uid,
            max_bytes=_MAX_FILE_BYTES,
        )
        if _identity(listed) != _identity(opened):
            raise LaunchVerificationError(
                "protected package entry changed during measurement"
            )
        try:
            path_bytes = relative.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise LaunchVerificationError(
                "protected package path is not UTF-8"
            ) from exc
        digest.update(len(path_bytes).to_bytes(8, "big"))
        digest.update(path_bytes)
        digest.update(stat.S_IMODE(opened.st_mode).to_bytes(4, "big"))
        digest.update(opened.st_size.to_bytes(8, "big"))
        digest.update(bytes.fromhex(file_digest[7:]))

    for directory, expected in directories:
        if _identity(os.lstat(directory)) != expected:
            raise LaunchVerificationError(
                "protected package changed during measurement"
            )
    return "sha256:" + digest.hexdigest()


def _validated_launch(
    identity_path: Path,
    broker_arguments: tuple[str, ...],
    *,
    expected_uid: int,
    launcher_path: Path,
) -> tuple[Path, tuple[str, ...], dict[str, str]]:
    identity_path = _require_absolute_real_path(
        str(identity_path),
        "release identity path",
    )
    document = _load_identity(identity_path, expected_uid)
    launcher = document["launcher"]
    package = document["package"]
    broker = document["broker"]
    python = document["python"]
    assert isinstance(launcher, dict)
    assert isinstance(package, dict)
    assert isinstance(broker, dict)
    assert isinstance(python, dict)
    if set(launcher) != {"digest", "path"}:
        raise LaunchVerificationError("launcher identity is invalid")
    if set(package) != {"root", "tree_digest"}:
        raise LaunchVerificationError("package identity is invalid")
    if set(broker) != {"digest", "path"}:
        raise LaunchVerificationError("broker identity is invalid")
    if set(python) != {"digest", "path"}:
        raise LaunchVerificationError("Python identity is invalid")

    expected_launcher = _require_absolute_real_path(
        launcher["path"],
        "launcher path",
    )
    actual_launcher = _require_absolute_real_path(
        str(launcher_path),
        "executed launcher path",
    )
    if expected_launcher != actual_launcher:
        raise LaunchVerificationError("executed launcher path is not pinned")
    _require_protected_ancestors(actual_launcher, expected_uid)
    launcher_digest, _metadata = _hash_regular_file(
        actual_launcher,
        expected_uid=expected_uid,
        max_bytes=_MAX_FILE_BYTES,
    )
    if launcher_digest != _require_digest(launcher["digest"], "launcher digest"):
        raise LaunchVerificationError("launcher digest does not match its pin")

    python_path = _require_absolute_real_path(python["path"], "Python path")
    observed_executable = _require_absolute_real_path(
        str(Path(sys.executable)),
        "running Python path",
    )
    observed_isolation = (
        bool(sys.flags.isolated)
        and bool(sys.flags.no_site)
        and bool(sys.flags.dont_write_bytecode)
    )
    if observed_executable != python_path or not observed_isolation:
        raise LaunchVerificationError(
            "launcher must run under pinned Python with -I -S -B"
        )
    _require_protected_ancestors(python_path, expected_uid)
    python_digest, _metadata = _hash_regular_file(
        python_path,
        expected_uid=expected_uid,
        max_bytes=256 * 1024 * 1024,
        executable=True,
    )
    if python_digest != _require_digest(python["digest"], "Python digest"):
        raise LaunchVerificationError("Python digest does not match its pin")

    package_root = _require_absolute_real_path(
        package["root"],
        "package root",
    )
    package_digest = _measure_package(package_root, expected_uid)
    if package_digest != _require_digest(
        package["tree_digest"],
        "package tree digest",
    ):
        raise LaunchVerificationError("package tree digest does not match its pin")

    broker_value = broker["path"]
    if not isinstance(broker_value, str):
        raise LaunchVerificationError("broker path is invalid")
    broker_relative = Path(broker_value)
    if (
        broker_relative.is_absolute()
        or "\\" in broker_value
        or any(part in {"", ".", ".."} for part in broker_relative.parts)
    ):
        raise LaunchVerificationError("broker path must be a normalized relative path")
    broker_path = _require_absolute_real_path(
        str(package_root.joinpath(*broker_relative.parts)),
        "broker path",
    )
    try:
        broker_path.relative_to(package_root)
    except ValueError as exc:
        raise LaunchVerificationError("broker path escapes its package") from exc
    broker_digest, _metadata = _hash_regular_file(
        broker_path,
        expected_uid=expected_uid,
        max_bytes=_MAX_FILE_BYTES,
    )
    if broker_digest != _require_digest(broker["digest"], "broker digest"):
        raise LaunchVerificationError("broker digest does not match its pin")

    argv = (
        str(python_path),
        "-I",
        "-S",
        "-B",
        str(broker_path),
        *broker_arguments,
    )
    return python_path, argv, dict(_ENVIRONMENT)


def _exec(
    executable: Path,
    argv: tuple[str, ...],
    environment: dict[str, str],
) -> None:
    os.chdir("/")
    os.umask(0o077)
    for value in os.listdir("/proc/self/fd"):
        if value.isdigit() and int(value) > 2:
            try:
                os.close(int(value))
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
    os.execve(executable, argv, environment)
    raise AssertionError("os.execve returned")


def main() -> int:
    if sys.platform != "linux" or os.geteuid() != 0:
        print(
            "aragorn protected launcher: Linux root execution is required",
            file=sys.stderr,
        )
        return 126
    if len(sys.argv) < 2 or sys.argv[1] != "--":
        print(
            "usage: aragorn-protected-install-launcher -- BROKER_ARGS...",
            file=sys.stderr,
        )
        return 126
    try:
        executable, argv, environment = _validated_launch(
            _IDENTITY_PATH,
            tuple(sys.argv[2:]),
            expected_uid=0,
            launcher_path=Path(__file__),
        )
        _exec(executable, argv, environment)
    except (LaunchVerificationError, OSError, ValueError) as exc:
        print(f"aragorn protected launcher: {exc}", file=sys.stderr)
        return 126
    raise AssertionError("launcher execution returned")


if __name__ == "__main__":
    raise SystemExit(main())
