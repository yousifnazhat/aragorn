"""Filesystem-backed, content-addressed blob storage."""

from __future__ import annotations

import errno
import hashlib
import os
from pathlib import Path
import secrets
import stat
from typing import BinaryIO, Callable


_CHUNK_SIZE = 1024 * 1024
_HEX = frozenset("0123456789abcdef")


class CASError(Exception):
    """The content-addressed store could not complete a safe operation."""


class CAS:
    """Store immutable blobs by SHA-256 digest."""

    def __init__(
        self, root: str | os.PathLike[str], *, read_only: bool = False
    ) -> None:
        self.root = Path(root)
        self.read_only = read_only
        self._sha_root = self.root / "blobs" / "sha256"
        root_stat = self._prepare_root()
        if stat.S_ISLNK(root_stat.st_mode):
            raise CASError(f"CAS root must not be a symlink: {self.root}")
        if not stat.S_ISDIR(root_stat.st_mode):
            raise CASError(f"CAS root is not a directory: {self.root}")
        if os.name == "posix":
            if root_stat.st_uid != os.geteuid():
                raise CASError(
                    f"CAS root is not owned by the current user: {self.root}"
                )
            if stat.S_IMODE(root_stat.st_mode) & 0o077:
                raise CASError(
                    f"CAS root grants group or other permissions: {self.root}"
                )
        self._prepare_internal_directories(create=not read_only)

    def put(self, source: BinaryIO, *, max_bytes: int) -> str:
        """Stream *source* into the store and return its ``sha256:`` digest."""

        return self._put(source, max_bytes=max_bytes, expected_hex=None)

    def put_expected(
        self,
        source: BinaryIO,
        *,
        expected_digest: str,
        max_bytes: int,
    ) -> str:
        """Publish *source* only when it matches an expected SHA-256 digest."""

        expected_hex = self._parse_digest(expected_digest)
        return self._put(
            source,
            max_bytes=max_bytes,
            expected_hex=expected_hex,
        )

    def _put(
        self,
        source: BinaryIO,
        *,
        max_bytes: int,
        expected_hex: str | None,
    ) -> str:
        """Stage one blob and link it only after all requested validation."""

        if self.read_only:
            raise CASError("CAS is read-only")
        if (
            isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or max_bytes < 0
        ):
            raise CASError("max_bytes must be a non-negative integer")

        fd = -1
        sha_fd = -1
        prefix_fd = -1
        temporary_name: str | None = None
        try:
            sha_fd = self._open_sha_root()
            fd, temporary_name = self._create_temporary_file(sha_fd, ".aragorn-put-")
            digest = hashlib.sha256()
            total = 0

            with os.fdopen(fd, "wb", closefd=True) as output:
                fd = -1
                while True:
                    chunk = source.read(min(_CHUNK_SIZE, max_bytes - total + 1))
                    if not isinstance(chunk, (bytes, bytearray, memoryview)):
                        raise CASError("source must be a binary stream")
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise CASError(f"blob exceeds max_bytes ({max_bytes})")
                    output.write(chunk)
                    digest.update(chunk)
                output.flush()
                os.fchmod(output.fileno(), 0o444)
                os.fsync(output.fileno())

            hex_digest = digest.hexdigest()
            if expected_hex is not None and hex_digest != expected_hex:
                raise CASError("blob digest does not match expected SHA-256 identity")
            digest_name = f"sha256:{hex_digest}"
            prefix_fd = self._open_digest_prefix(sha_fd, hex_digest[:2], create=True)

            try:
                os.link(
                    temporary_name,
                    hex_digest[2:],
                    src_dir_fd=sha_fd,
                    dst_dir_fd=prefix_fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                self._stream_verified(digest_name)
            else:
                os.fsync(prefix_fd)
                os.fsync(sha_fd)
            return digest_name
        except CASError:
            raise
        except (OSError, TypeError, ValueError) as exc:
            raise CASError(f"cannot store blob: {exc}") from exc
        finally:
            if fd >= 0:
                os.close(fd)
            if temporary_name is not None and sha_fd >= 0:
                try:
                    os.unlink(temporary_name, dir_fd=sha_fd)
                except OSError:
                    pass
            if prefix_fd >= 0:
                os.close(prefix_fd)
            if sha_fd >= 0:
                os.close(sha_fd)

    def read(self, digest: str, *, max_bytes: int | None = None) -> bytes:
        """Return a blob only after verifying its digest."""
        self._validate_max_bytes(max_bytes)
        data = bytearray()
        self._stream_verified(digest, data.extend, max_bytes=max_bytes)
        return bytes(data)

    def verify(self, digest: str, *, max_bytes: int | None = None) -> None:
        """Stream and verify a blob without retaining it in memory."""

        self._validate_max_bytes(max_bytes)
        self._stream_verified(digest, max_bytes=max_bytes)

    @staticmethod
    def _validate_max_bytes(max_bytes: int | None) -> None:
        if max_bytes is not None and (
            isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or max_bytes < 0
        ):
            raise CASError("max_bytes must be a non-negative integer")

    def materialize(
        self,
        digest: str,
        destination: str | os.PathLike[str],
        *,
        root: str | os.PathLike[str],
    ) -> Path:
        """Atomically create *destination* below an explicit trusted *root*."""
        target = Path(destination)
        root_path = Path(os.path.abspath(os.fspath(root)))
        target_path = Path(os.path.abspath(os.fspath(target)))
        try:
            relative = target_path.relative_to(root_path)
        except ValueError as exc:
            raise CASError(
                f"destination is outside materialization root: {target}"
            ) from exc
        if not relative.parts or not target.name or ".." in relative.parts:
            raise CASError(f"invalid materialization destination: {target}")

        fd = -1
        parent_fd = -1
        temporary_name: str | None = None
        try:
            parent_fd = self._open_directory_no_symlinks(root_path, relative.parent)
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            for _ in range(100):
                candidate = f".aragorn-materialize-{secrets.token_hex(12)}"
                try:
                    fd = os.open(candidate, flags, 0o600, dir_fd=parent_fd)
                except FileExistsError:
                    continue
                temporary_name = candidate
                break
            if fd < 0 or temporary_name is None:
                raise CASError("cannot allocate a temporary materialization file")

            with os.fdopen(fd, "wb", closefd=True) as output:
                fd = -1
                self._stream_verified(digest, output.write)
                output.flush()
                os.fchmod(output.fileno(), 0o444)
                os.fsync(output.fileno())

            try:
                os.link(
                    temporary_name,
                    target.name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except FileExistsError as exc:
                raise CASError(f"destination already exists: {target}") from exc
            os.fsync(parent_fd)
            return target
        except CASError:
            raise
        except (OSError, TypeError, ValueError) as exc:
            raise CASError(f"cannot materialize {digest}: {exc}") from exc
        finally:
            if fd >= 0:
                os.close(fd)
            if temporary_name is not None and parent_fd >= 0:
                try:
                    os.unlink(temporary_name, dir_fd=parent_fd)
                except OSError:
                    pass
            if parent_fd >= 0:
                os.close(parent_fd)

    @staticmethod
    def _open_directory_no_symlinks(root: Path, relative: Path) -> int:
        if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
            raise CASError("safe materialization is unsupported on this platform")
        if relative.is_absolute() or ".." in relative.parts:
            raise CASError(f"invalid destination parent below {root}: {relative}")

        flags = (
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            current_fd = os.open(root, flags)
        except OSError as exc:
            raise CASError(f"cannot open materialization root {root}: {exc}") from exc

        try:
            for part in relative.parts:
                if part in {"", "."}:
                    continue
                try:
                    next_fd = os.open(part, flags, dir_fd=current_fd)
                except OSError as exc:
                    raise CASError(
                        "destination parent contains a symlink or non-directory "
                        f"component below {root}: {relative}"
                    ) from exc
                os.close(current_fd)
                current_fd = next_fd
            return current_fd
        except BaseException:
            os.close(current_fd)
            raise

    def _prepare_root(self) -> os.stat_result:
        try:
            return os.lstat(self.root)
        except FileNotFoundError as exc:
            if self.read_only:
                raise CASError(f"CAS root does not exist: {self.root}") from exc
        except OSError as exc:
            raise CASError(f"cannot inspect CAS root {self.root}: {exc}") from exc

        created = False
        try:
            self.root.mkdir(mode=0o700, parents=True)
        except FileExistsError:
            pass
        except OSError as exc:
            raise CASError(f"cannot create CAS root {self.root}: {exc}") from exc
        else:
            created = True

        try:
            if os.name == "posix" and created:
                flags = (
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                fd = os.open(self.root, flags)
                try:
                    os.fchmod(fd, 0o700)
                    return os.fstat(fd)
                finally:
                    os.close(fd)
            return os.lstat(self.root)
        except OSError as exc:
            raise CASError(f"cannot secure CAS root {self.root}: {exc}") from exc

    def _prepare_internal_directories(self, *, create: bool) -> None:
        if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
            raise CASError("safe CAS initialization is unsupported on this platform")
        flags = (
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            current_fd = os.open(self.root, flags)
        except OSError as exc:
            raise CASError(f"cannot open CAS root safely: {exc}") from exc

        try:
            for component in ("blobs", "sha256"):
                if create:
                    try:
                        os.mkdir(component, mode=0o700, dir_fd=current_fd)
                    except FileExistsError:
                        pass
                    except OSError as exc:
                        raise CASError(
                            f"cannot create CAS directory {component}: {exc}"
                        ) from exc
                try:
                    next_fd = os.open(component, flags, dir_fd=current_fd)
                except OSError as exc:
                    raise CASError(
                        f"CAS directory {component} must be a real directory: {exc}"
                    ) from exc
                metadata = os.fstat(next_fd)
                if os.name == "posix":
                    if metadata.st_uid != os.geteuid():
                        os.close(next_fd)
                        raise CASError(
                            f"CAS directory {component} is not owned by the current user"
                        )
                    if stat.S_IMODE(metadata.st_mode) & 0o077:
                        os.close(next_fd)
                        raise CASError(
                            f"CAS directory {component} grants group or other permissions"
                        )
                os.close(current_fd)
                current_fd = next_fd
        finally:
            os.close(current_fd)

    def _open_sha_root(self) -> int:
        flags = (
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        )
        descriptors: list[int] = []
        try:
            current = os.open(self.root, flags)
            descriptors.append(current)
            for component in ("blobs", "sha256"):
                current = os.open(component, flags, dir_fd=current)
                descriptors.append(current)
            result = descriptors.pop()
            return result
        except OSError as exc:
            raise CASError(f"cannot open CAS directories safely: {exc}") from exc
        finally:
            for descriptor in descriptors:
                os.close(descriptor)

    @staticmethod
    def _open_digest_prefix(sha_fd: int, prefix: str, *, create: bool) -> int:
        if len(prefix) != 2 or any(character not in _HEX for character in prefix):
            raise CASError("invalid CAS digest prefix")
        if create:
            try:
                os.mkdir(prefix, mode=0o700, dir_fd=sha_fd)
            except FileExistsError:
                pass
            except OSError as exc:
                raise CASError(
                    f"cannot create CAS digest prefix {prefix}: {exc}"
                ) from exc
        flags = (
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            descriptor = os.open(prefix, flags, dir_fd=sha_fd)
        except OSError as exc:
            raise CASError(
                f"CAS digest prefix {prefix} must be a real directory: {exc}"
            ) from exc
        metadata = os.fstat(descriptor)
        if os.name == "posix" and (
            metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            os.close(descriptor)
            raise CASError(
                f"CAS digest prefix {prefix} has unsafe ownership or permissions"
            )
        return descriptor

    @staticmethod
    def _create_temporary_file(parent_fd: int, prefix: str) -> tuple[int, str]:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        for _ in range(100):
            name = f"{prefix}{secrets.token_hex(12)}"
            try:
                return os.open(name, flags, 0o600, dir_fd=parent_fd), name
            except FileExistsError:
                continue
        raise CASError("cannot allocate a temporary CAS file")

    @staticmethod
    def _parse_digest(digest: str) -> str:
        if not isinstance(digest, str) or not digest.startswith("sha256:"):
            raise CASError("digest must use the sha256:<hex> form")
        value = digest.removeprefix("sha256:")
        if len(value) != 64 or any(character not in _HEX for character in value):
            raise CASError("digest must contain 64 lowercase hexadecimal characters")
        return value

    def _stream_verified(
        self,
        digest: str,
        write: Callable[[bytes], object] | None = None,
        *,
        max_bytes: int | None = None,
    ) -> None:
        expected = self._parse_digest(digest)
        fd = -1
        sha_fd = -1
        prefix_fd = -1
        try:
            sha_fd = self._open_sha_root()
            prefix_fd = self._open_digest_prefix(sha_fd, expected[:2], create=False)
            before = os.stat(expected[2:], dir_fd=prefix_fd, follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode):
                raise CASError(f"blob is not a regular file: {digest}")
            if max_bytes is not None and before.st_size > max_bytes:
                raise CASError(f"blob exceeds max_bytes ({max_bytes}): {digest}")

            flags = (
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            )
            fd = os.open(expected[2:], flags, dir_fd=prefix_fd)
            opened = os.fstat(fd)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise CASError(f"blob changed while opening: {digest}")
            if max_bytes is not None and opened.st_size > max_bytes:
                raise CASError(f"blob exceeds max_bytes ({max_bytes}): {digest}")

            actual = hashlib.sha256()
            total = 0
            with os.fdopen(fd, "rb", closefd=True) as blob:
                fd = -1
                while chunk := blob.read(_CHUNK_SIZE):
                    total += len(chunk)
                    if max_bytes is not None and total > max_bytes:
                        raise CASError(
                            f"blob exceeds max_bytes ({max_bytes}): {digest}"
                        )
                    actual.update(chunk)
                    if write is not None:
                        write(chunk)
                after = os.fstat(blob.fileno())
            opened_identity = (
                opened.st_dev,
                opened.st_ino,
                opened.st_mode,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            )
            after_identity = (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            if opened_identity != after_identity:
                raise CASError(f"blob changed while reading: {digest}")
            if actual.hexdigest() != expected:
                raise CASError(f"blob failed digest verification: {digest}")
        except CASError:
            raise
        except (OSError, TypeError, ValueError) as exc:
            if isinstance(exc, OSError) and exc.errno == errno.ENOENT:
                raise CASError(f"blob not found: {digest}") from exc
            raise CASError(f"cannot read blob {digest}: {exc}") from exc
        finally:
            if fd >= 0:
                os.close(fd)
            if prefix_fd >= 0:
                os.close(prefix_fd)
            if sha_fd >= 0:
                os.close(sha_fd)
